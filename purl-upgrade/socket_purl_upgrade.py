#!/usr/bin/env python3
"""Build a Socket upgrade plan for a batch of package URLs (purls).

For every input purl the script reports:

  1. input_purl        -- the purl exactly as it appeared in the input
  2. newest_version    -- newest release in the upstream registry (stable by default)
  3. safe_version      -- newest version with no actionable Socket alerts (blank if none)
  4. fixes_api_version -- Socket Fixes API's dependency-graph-aware fix version for any
                          known CVE on the input version (blank if no CVE, or ecosystem
                          not wired up for the cross-reference -- see below)
  5. recommendation    -- replacement package > Fixes API fix > newest safe version > newest version

It also emits every Socket alert for every input purl (with the GHSA id and the
"socket fix" hint Socket attaches to fixable ones), deprecated / unmaintained status
for both the input version and the package itself, the replacement package where the
registry (or the deprecation notice) names one, Socket's own 0-100 scores per category,
a best-effort package/version age, and human-facing registry + source-code links.

What counts as "actionable" for safe_version is set by --safe-mode:

  policy   (default) alerts your org security policy acts on (--safe-actions,
           default error,warn). Socket flags routine behaviour (networkAccess,
           filesystemAccess, envVars ...) on almost every package, so "zero
           alerts of any kind" would return a blank safe_version nearly always.
  severity high/critical alerts plus anything in vulnerability, malware,
           deprecated or unmaintained, regardless of policy.
  strict   literal: any Socket alert at all disqualifies a version.

Versions Socket has not analyzed (notFound / pendingScan) are never called safe;
they are reported in the notes column instead.

Fixes API cross-reference: for every input purl carrying a known CVE (a GHSA-bearing
vulnerability alert), the script synthesizes minimal, exact-pinned manifests for that
ecosystem (package.json / requirements.txt / pom.xml) in chunks of 40 packages (the
graph resolution behind /fixes times out on very large single manifests; same-name
different-version inputs also go in separate chunks so every pin survives), uploads
each with upload-manifest-files, and asks GET /orgs/{org}/fixes for the
dependency-graph-aware fix version -- the same engine behind `socket fix`. This is
more precise than safe_version's brute-force "probe versions until Socket stops
alerting" approach: it accounts for transitive fixes and reports updateType
(patch/minor/major), CISA KEV status, and EPSS. Wired up for npm, pypi, and maven;
other ecosystems fall back to safe_version alone. Disable with --no-fixes-api; gate
suggested versions by age with --minimum-release-age.

Everything is deterministic: alerts, scores, and fixes come from Socket's API, versions
and deprecations come from the upstream registries, and the recommendation is a fixed
priority rule.

Usage:
    export SOCKET_API_KEY=...            # or SOCKET_SECURITY_API_TOKEN
    python3 socket_purl_upgrade.py "input.csv" --org my-org-slug --out upgrade_report

Input may be a CSV (purl column auto-detected, override with --purl-column) or a
text file with one purl per line. Uppercased purls, %40 scopes and 'v' prefixes
are all handled.

Outputs (<out>.csv/_alerts.csv/_alert_summary.csv and a 4-sheet <out>.xlsx):
    upgrade_plan   one row per input purl, columns above plus supporting detail
    alerts         one row per Socket alert on each input purl
    alert_summary  alert type rollup (packages affected, occurrences)
    run_info       settings and counts for the run

Version/deprecation lookup: npm, nuget, pypi, maven, golang, cargo, gem, github,
apk (alpine). Socket alert coverage is whatever the purl API returns; ecosystems
it does not analyze (e.g. apk) come back notFound and get a blank safe_version.
"""
import argparse
import base64
import csv
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

SOCKET_API_BASE = "https://api.socket.dev/v0"
# repo1.maven.org returns 403 to any User-Agent containing the substring
# "socket" (case-insensitive, verified 2026-09-01), which silently killed every
# Maven lookup. Keep the tool name honest but free of that substring.
USER_AGENT = "purl-upgrade/2.0"
DEFAULT_CACHE = os.path.expanduser("~/.cache/socket_purl_upgrade")
CACHE_TTL = 24 * 3600
# Folded into every cache key. Bump when a change alters what gets fetched or
# stored for a URL, or entries written by older code keep being served until
# their TTL expires (this bit the npm publish-date fix: the corrected code kept
# reading day-old docs cached without the `time` map).
CACHE_SCHEMA = "v2"

PLAN_COLUMNS = [
    "input_purl",
    "newest_version",
    "safe_version",
    "fixes_api_version",
    "recommendation",
    "recommendation_type",
    "recommended_purl",
    "ecosystem",
    "package_name",
    "registry_link",
    "source_code_link",
    "input_version",
    "input_is_newest",
    "socket_found",
    "input_alert_count",
    "input_actionable_alert_count",
    "input_max_severity",
    "input_alert_types",
    "input_ghsas",
    "fixes_api_update_type",
    "fixes_api_kev",
    "fixes_api_max_epss",
    "fixes_api_note",
    "socket_overall_score",
    "socket_supply_chain_score",
    "socket_quality_score",
    "socket_maintenance_score",
    "socket_vulnerability_score",
    "socket_license_score",
    "input_version_deprecated",
    "package_deprecated",
    "is_unmaintained",
    "input_version_published_at",
    "input_version_age_days",
    "age_source",
    "last_publish",
    "package_last_release_days",
    "stale_package",
    "deprecation_reason",
    "replacement_package",
    "replacement_newest_version",
    "replacement_source",
    "versions_probed",
    "notes",
]
ALERT_COLUMNS = [
    "input_purl",
    "ecosystem",
    "package_name",
    "version",
    "alert_type",
    "severity",
    "category",
    "action",
    "actionable",
    "ghsa_id",
    "fix_hint",
    "detail",
    "props",
]
SUMMARY_COLUMNS = ["alert_type", "category", "severity", "action", "packages", "occurrences"]

SEVERITY_RANK = {"low": 1, "middle": 2, "high": 3, "critical": 4}
ACTION_RANK = {"error": 4, "warn": 3, "monitor": 2, "ignore": 1, "": 0}
# Any dash-suffix is a prerelease in these ecosystems (SemVer / NuGet rules).
SEMVER_ECOSYSTEMS = {"npm", "nuget", "cargo", "golang", "github", "hex", "swift"}
PRERELEASE_WORDS = {
    "alpha", "beta", "rc", "pre", "prerelease", "preview", "dev", "snapshot",
    "nightly", "canary", "next", "milestone", "cr", "insiders", "unstable", "eap",
}
POST_WORDS = {"post", "p", "git", "hg", "svn", "cvs"}
# Words that describe how finished a release is, not which line it belongs to.
# "ga" on rel_3_33_0_ga is a status, so it must never open a release stream.
RELEASE_STATUS_WORDS = {
    "ga", "final", "release", "stable", "rel", "fcs", "sr", "sec", "patch",
}
# PEP440 / Maven style markers that open a prerelease segment: 1.0b1, 5.0.0-M2, 2.0a3
PRERELEASE_HEAD_RE = re.compile(
    r"^(?:alpha|beta|rc|prerelease|preview|pre|dev|snapshot|nightly|canary|next"
    r"|milestone|cr|eap|unstable|insiders|[abcm])\d*(?:$|[._\-+])"
)

# Ecosystems the Fixes API cross-reference knows how to synthesize a manifest for.
FIXES_API_ECOSYSTEMS = {"npm", "pypi", "maven"}
# Ecosystems Socket itself analyses. Outside these a clean row means "no data",
# not "no risk", and the report has to say which.
# Verified against the purl API rather than the docs page, because the two
# disagree: composer and swift both come back scored with real alerts, and
# huggingface is scored, while docker, conan and hex answer notFound and
# openvsx isn't a recognised purl type here at all. Getting this wrong prints
# a false disclaimer, so re-probe before editing.
SOCKET_ANALYZED_ECOSYSTEMS = {
    "npm", "pypi", "maven", "nuget", "golang", "cargo", "gem", "github",
    "composer", "swift", "huggingface",
}
# Packages per synthesized manifest / fixes call. The Fixes API resolves the
# whole dependency graph server-side; measured live, ~40 packages resolves in
# ~50s, 100 takes ~260s, and 200+ times out entirely. 40 keeps each call well
# inside the timeout with room for slow days.
FIXES_CHUNK = 40


# --------------------------------------------------------------------------- #
# http + cache
# --------------------------------------------------------------------------- #

class Http:
    def __init__(self, cache_dir, ttl=CACHE_TTL, use_cache=True, verbose=False):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.use_cache = use_cache
        self.verbose = verbose
        if use_cache:
            os.makedirs(cache_dir, exist_ok=True)

    def _cache_path(self, key):
        digest = hashlib.sha1(f"{CACHE_SCHEMA}:{key}".encode()).hexdigest()
        return os.path.join(self.cache_dir, digest + ".json")

    def cached_json(self, url, headers=None, parser=None, retries=3):
        """GET url, returning parsed JSON (or parser(bytes)), cached on disk."""
        path = self._cache_path(url)
        if self.use_cache and os.path.exists(path):
            age = time.time() - os.path.getmtime(path)
            if age < self.ttl:
                try:
                    with open(path) as fh:
                        return json.load(fh)
                except (OSError, ValueError):
                    pass
        raw = self.get(url, headers=headers, retries=retries)
        if raw is None:
            return None
        try:
            value = parser(raw) if parser else json.loads(raw)
        except Exception as err:  # noqa: BLE001 - registry gave us junk
            if self.verbose:
                print(f"  parse failed for {url}: {err}", file=sys.stderr)
            return None
        if self.use_cache:
            tmp = path + f".{os.getpid()}.{threading.get_ident()}.tmp"
            try:
                with open(tmp, "w") as fh:
                    json.dump(value, fh)
                os.replace(tmp, path)
            except OSError:
                pass
        return value

    def get(self, url, headers=None, retries=3):
        hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
        if headers:
            hdrs.update(headers)
        for attempt in range(1, retries + 1):
            try:
                req = urllib.request.Request(url, headers=hdrs)
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read()
                    if resp.headers.get("Content-Encoding") == "gzip":
                        data = gzip.decompress(data)
                    return data
            except urllib.error.HTTPError as err:
                if err.code in (404, 410):
                    return None
                if err.code in (429, 500, 502, 503, 504) and attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                if self.verbose:
                    print(f"  {err.code} for {url}", file=sys.stderr)
                return None
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                if attempt < retries:
                    time.sleep(2 ** attempt)
                    continue
                if self.verbose:
                    print(f"  {err} for {url}", file=sys.stderr)
                return None
        return None


# --------------------------------------------------------------------------- #
# purl parsing
# --------------------------------------------------------------------------- #

class Purl:
    __slots__ = ("raw", "type", "namespace", "name", "version", "qualifiers", "subpath")

    def __init__(self, raw, type_, namespace, name, version, qualifiers, subpath):
        self.raw = raw
        self.type = type_
        self.namespace = namespace
        self.name = name
        self.version = version
        self.qualifiers = qualifiers
        self.subpath = subpath

    @property
    def full_name(self):
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name

    def without_version(self):
        """Copy of this purl with the version dropped (for package-level links)."""
        return Purl(self.raw, self.type, self.namespace, self.name, None,
                    self.qualifiers, self.subpath)

    def with_version(self, version):
        body = self.type + "/"
        if self.namespace:
            body += "/".join(quote_segment(s) for s in self.namespace.split("/")) + "/"
        body += quote_segment(self.name)
        out = "pkg:" + body + "@" + urllib.parse.quote(version, safe=".+_~!$&'()*,;=:")
        if self.qualifiers:
            out += "?" + "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in sorted(self.qualifiers.items()))
        if self.subpath:
            out += "#" + self.subpath
        return out

    def socket_purl(self, version):
        """Canonical purl for Socket queries: no qualifiers, no subpath.

        Verified live: when one batch contains two spellings of the same
        package+version (bare vs ?type=jar, @scope vs %40scope), Socket's purl
        endpoint dedupes them server-side and returns the real record under ONE
        of the spellings and notFound under the other -- which spelling wins is
        arbitrary. Always querying the canonical spelling makes every row that
        refers to the same package+version share one deterministic record.
        """
        body = self.type + "/"
        if self.namespace:
            body += "/".join(quote_segment(s) for s in self.namespace.split("/")) + "/"
        body += quote_segment(self.name)
        out = "pkg:" + body
        if version:
            out += "@" + urllib.parse.quote(version, safe=".+_~!$&'()*,;=:")
        return out


def quote_segment(segment):
    return urllib.parse.quote(segment, safe="@.+_~!$&'()*,;=:")


def parse_purl(raw):
    """Parse a purl string. Tolerates uppercase input and 'v'-prefixed versions."""
    text = raw.strip().strip('"')
    if not text:
        return None
    if not text.lower().startswith("pkg:"):
        return None
    body = text[4:].lstrip("/")
    body, _, subpath = body.partition("#")
    body, _, query = body.partition("?")
    qualifiers = {}
    for part in query.split("&"):
        if "=" in part:
            key, _, value = part.partition("=")
            qualifiers[key.strip().lower()] = urllib.parse.unquote(value.strip())
    type_, _, rest = body.partition("/")
    type_ = type_.strip().lower()
    if not rest:
        return None
    at = rest.rfind("@")
    if at > 0:
        path, version = rest[:at], urllib.parse.unquote(rest[at + 1:])
    else:
        path, version = rest, ""
    segments = [urllib.parse.unquote(s) for s in path.split("/") if s]
    if not segments:
        return None
    name = segments[-1]
    namespace = "/".join(segments[:-1])
    namespace, name = normalize_name(type_, namespace, name)
    if "arch" in qualifiers:
        qualifiers["arch"] = qualifiers["arch"].lower()
    return Purl(text, type_, namespace, name, normalize_version(type_, version.strip()),
                qualifiers, subpath)


LOWERCASE_VERSION_ECOSYSTEMS = {"apk", "github", "deb", "rpm"}


def normalize_version(eco, version):
    """Registries whose version strings are canonically lowercase (some scanner exports upcase input)."""
    return version.lower() if eco in LOWERCASE_VERSION_ECOSYSTEMS else version


def reconcile_version(eco, version, known_versions):
    """Adopt the registry's exact spelling for versions that are the same
    release written differently: case (some scanner exports upcase input), PEP 440 zero-padding
    (pypi 2.2.0 vs the published 2.2), and golang's v prefix (1.6.3 vs v1.6.3).
    Socket's purl endpoint returns notFound for the unpublished spelling
    (verified live), so this is what makes such rows resolve at all."""
    if not version:
        return version
    for candidate in known_versions or []:
        if candidate == version:
            return version
    lowered = version.lower()
    for candidate in known_versions or []:
        if candidate.lower() == lowered:
            return candidate
    if eco in ("pypi", "golang"):
        # Safe here because neither registry can publish two distinct versions
        # that normalize to the same release (PEP 440 / go module rules).
        key = version_key(eco, version)
        for candidate in known_versions or []:
            if version_key(eco, candidate) == key:
                return candidate
    return version


def normalize_name(eco, namespace, name):
    """Case/format normalization that is safe per ecosystem."""
    if eco == "npm":
        namespace, name = namespace.lower(), name.lower()
        if namespace and not namespace.startswith("@"):
            namespace = "@" + namespace
    elif eco in ("nuget", "apk", "github", "deb", "rpm", "cargo", "gem", "cocoapods", "hex"):
        namespace, name = namespace.lower(), name.lower()
    elif eco == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
        namespace = namespace.lower()
    return namespace, name


def registry_link(purl, info=None):
    """Human-facing registry page for a purl. Pure and deterministic -- no I/O.

    `info` is an optional already-fetched registry record; when it carries
    coordinates that actually resolved (maven casing), those win over the
    input purl's spelling so the link doesn't 404.
    """
    eco, name, version = purl.type, purl.full_name, purl.version
    info = info or {}
    if eco == "npm":
        return f"https://www.npmjs.com/package/{name}" + (f"/v/{version}" if version else "")
    if eco == "pypi":
        return f"https://pypi.org/project/{name}/" + (f"{version}/" if version else "")
    if eco == "maven" and purl.namespace:
        group = info.get("resolved_namespace") or purl.namespace
        artifact = info.get("resolved_name") or purl.name
        base = f"https://central.sonatype.com/artifact/{group}/{artifact}"
        return base + (f"/{version}" if version else "")
    if eco == "golang":
        return f"https://pkg.go.dev/{name}" + (f"@{version}" if version else "")
    if eco == "cargo":
        return f"https://crates.io/crates/{name}" + (f"/{version}" if version else "")
    if eco == "gem":
        return f"https://rubygems.org/gems/{name}" + (f"/versions/{version}" if version else "")
    if eco == "nuget":
        return f"https://www.nuget.org/packages/{name}" + (f"/{version}" if version else "")
    if eco == "github" and purl.namespace:
        return f"https://github.com/{name}" + (f"/releases/tag/{version}" if version else "")
    if eco == "cpan":
        return f"https://metacpan.org/dist/{purl.name}"
    if eco == "apk":
        arch = purl.qualifiers.get("arch", "x86_64")
        return f"https://pkgs.alpinelinux.org/package/edge/main/{arch}/{name}"
    return ""


def _clean_repo_url(url):
    """Normalize the assorted repository-URL spellings package.json/Cargo.toml use."""
    url = (url or "").strip()
    if not url:
        return ""
    url = re.sub(r"^git\+", "", url)
    url = re.sub(r"^git://", "https://", url)
    match = re.match(r"^git@([\w.\-]+):(.+?)(\.git)?$", url)
    if match:
        return f"https://{match.group(1)}/{match.group(2)}"
    if url.startswith("github:"):
        return "https://github.com/" + url[len("github:"):]
    url = re.sub(r"\.git$", "", url)
    return url


def _parse_iso(text):
    """Tolerant date parse for the formats the registries and Socket return.

    Covers ISO-8601, Maven's 14-digit lastUpdated stamp, and the RFC 2822 dates
    that come back on Socket's unmaintained alert props. Always tz-aware, so
    callers can subtract it from utcnow without tripping over naive datetimes.
    """
    text = str(text or "").strip()
    if not text:
        raise ValueError("empty date")
    if re.fullmatch(r"\d{14}", text):  # maven-metadata lastUpdated
        return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = parsedate_to_datetime(text)  # "Tue, 22 Nov 2005 18:06:33 GMT"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# --------------------------------------------------------------------------- #
# version ordering
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")
_RELEASE_RE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")
# Git tags rarely arrive as bare versions. Strip a leading marker or repo-name
# prefix so rel_3_32_0_ga, r5.10.0 and jcodings-1.0.64 rank by their numbers
# instead of collapsing to release 0 and losing to any prerelease.
_TAG_MARKER_RE = re.compile(r"^(?:rel(?:ease)?|ver(?:sion)?|[vr])[-_.]?(?=\d)", re.I)
_TAG_NAME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*)[-_][vV]?(?=\d)")


def strip_tag_prefix(text):
    """Drop a leading tag marker or repo-name prefix from a version string."""
    text = str(text or "").strip()
    match = _TAG_MARKER_RE.match(text)
    if match:
        return text[match.end():]
    match = _TAG_NAME_RE.match(text)
    if match:
        # never strip a word that carries release-stage meaning: alpha-1 is a
        # prerelease of 1, not a package called "alpha"
        prefix = match.group(1).lower()
        words = {w for w in re.findall(r"[A-Za-z]+", prefix)}
        if not (words & PRERELEASE_WORDS or words & POST_WORDS
                or PRERELEASE_HEAD_RE.match(prefix)):
            return text[match.end():]
    return text


def _tokens(text):
    out = []
    for tok in _TOKEN_RE.findall(text):
        if tok.isdigit():
            out.append((0, int(tok), ""))
        else:
            out.append((1, 0, tok.lower()))
    return tuple(out)


def _trim(nums):
    nums = list(nums)
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return tuple(nums)


def version_key(eco, version):
    """Sortable key for a version string within one ecosystem."""
    text = strip_tag_prefix(version)
    extra = ()
    if eco == "apk":
        match = re.match(r"^(.*)-r(\d+)$", text)
        if match:
            text, extra = match.group(1), (int(match.group(2)),)
        text = text.replace("_", "-", 1)
    text = text.partition("+")[0]
    match = _RELEASE_RE.match(text)
    if match:
        release = _trim(tuple(int(x) for x in match.group(1).split(".")))
        tail = match.group(2)
    else:
        release, tail = (0,), text
    # CPAN marks developer/trial releases with an underscore in the version
    # (JSON-PP 4.17_01). They are prereleases by convention and never indexed
    # as latest, so rank them below the release they precede.
    if eco == "cpan" and "_" in text:
        return (release, 0, _tokens(tail), extra)
    dashed = tail.startswith("-")
    tail = tail.lstrip("-._")
    rank = 1
    if tail:
        words = {w for w in re.findall(r"[A-Za-z]+", tail.lower())}
        if eco in SEMVER_ECOSYSTEMS and dashed:
            # SemVer/NuGet: a dash opens the prerelease segment, no exceptions.
            # Only a dash, though. Git tags in these ecosystems separate with
            # underscores and dots (javassist ships rel_3_33_0_ga, where _ga
            # means general availability), and calling those prereleases is
            # the opposite of what the tag says.
            rank = 0
        elif words & PRERELEASE_WORDS or PRERELEASE_HEAD_RE.match(tail.lower()):
            rank = 0
        elif words & POST_WORDS:
            rank = 2
    return (release, rank, _tokens(tail), extra)


def is_prerelease(eco, version):
    return version_key(eco, version)[1] == 0


def release_stream(eco, version):
    """Identify a parallel distribution stream, or "" for the mainline.

    Some packages ship several streams side by side under one coordinate, each
    with its own numbering: Kafka's OSS `4.3.1` next to Confluent's `8.3.1-ce`
    and `8.3.1-ccs`, or Guava's `33.4.8-jre` next to `33.4.8-android`. The
    numbers are not comparable across streams, so "highest number wins" will
    happily recommend a vendor build to someone on OSS, or the reverse.

    A stream is the alphabetic part of a version's qualifier tail. Numeric-only
    tails (`1.2.3-1`, a rebuild) stay on the mainline, and prereleases are
    excluded here because `1.0.0-rc1` is a stage of the mainline, not a
    separate stream -- is_prerelease already handles those.
    """
    text = strip_tag_prefix(version)
    if not text:
        return ""
    # Git tags are freeform text, not coordinates with vendor variants. Reading
    # streams out of them splits one project's own history apart: javassist
    # tags rel_3_33_0_ga, and treating "ga" as a stream hides its newest
    # release behind whichever tag happens to lack a suffix.
    if eco in ("github", "bitbucket", "gitlab"):
        return ""
    key = version_key(eco, text)
    if key[1] != 1:  # prerelease or post-release, not a parallel stream
        return ""
    # Work on separator-delimited segments, not letter runs. A stream tag is a
    # whole word (ce, ccs, jre, android, spark); a segment that mixes letters
    # and digits is a build identifier -- 1.9.117-592b42f is a commit hash, and
    # reading "b" and "f" out of it invents streams that don't exist.
    tail = _RELEASE_RE.match(text)
    tail = tail.group(2) if tail else text
    words = [seg.lower() for seg in re.split(r"[.\-_+~]+", tail)
             if seg.isalpha() and len(seg) > 1
             and seg.lower() not in RELEASE_STATUS_WORDS]
    return ".".join(words)


def same_stream(eco, a, b):
    return release_stream(eco, a) == release_stream(eco, b)


def newest(eco, versions):
    usable = [v for v in versions if v]
    if not usable:
        return None
    return max(usable, key=lambda v: version_key(eco, v))


# --------------------------------------------------------------------------- #
# registry clients
# --------------------------------------------------------------------------- #

def empty_registry(source="", error=""):
    return {
        "versions": [], "latest": None, "unusable": {}, "deprecated": {}, "alternates": {},
        "display_name": "", "alternate": None, "alternate_range": "",
        "last_publish": "", "source": source, "error": error,
        "repo_url": "", "publish_dates": {},
        "resolved_namespace": "", "resolved_name": "", "notes": "",
    }


def npm_registry(http, purl):
    info = empty_registry()
    name = purl.full_name
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    info["source"] = url
    # Full metadata, not the abbreviated "install" format (Accept:
    # vnd.npm.install-v1+json) -- the abbreviated form drops the `time` map
    # entirely (verified live), which is the only source of per-version
    # publish dates npm's registry offers. One request either way; this one
    # is just a bigger payload, and the on-disk cache absorbs repeat runs.
    doc = http.cached_json(url)
    if not doc:
        info["error"] = "npm registry lookup failed"
        return info
    info["display_name"] = doc.get("name") or name
    versions = doc.get("versions") or {}
    info["versions"] = list(versions.keys())
    info["latest"] = (doc.get("dist-tags") or {}).get("latest")
    for version, meta in versions.items():
        note = meta.get("deprecated")
        if isinstance(note, str) and note.strip():
            info["deprecated"][version] = note.strip()
    times = doc.get("time") or {}
    info["publish_dates"] = {v: t for v, t in times.items() if v not in ("created", "modified")}
    if info["latest"] and info["latest"] in times:
        info["last_publish"] = times[info["latest"]]
    elif times.get("modified"):
        info["last_publish"] = times["modified"]
    repo_meta = versions.get(purl.version) or (versions.get(info["latest"]) if info.get("latest") else None)
    if repo_meta:
        repo = repo_meta.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url", "")
        if isinstance(repo, str) and repo:
            info["repo_url"] = _clean_repo_url(repo)
    return info


def nuget_registry(http, purl):
    info = empty_registry()
    ident = purl.name.lower()
    reg_url = f"https://api.nuget.org/v3/registration5-gz-semver2/{urllib.parse.quote(ident)}/index.json"
    info["source"] = reg_url
    index = http.cached_json(reg_url)
    pages = []
    if index:
        for page in index.get("items") or []:
            if page.get("items"):
                pages.append(page)
            else:
                page_url = page.get("@id")
                leaf = http.cached_json(page_url) if page_url else None
                if leaf:
                    pages.append(leaf)
    for page in pages:
        for leaf in page.get("items") or []:
            entry = leaf.get("catalogEntry") or {}
            version = entry.get("version")
            if not version:
                continue
            info["versions"].append(version)
            if entry.get("id"):
                info["display_name"] = entry["id"]
            if entry.get("listed") is False:
                info["unusable"][version] = "unlisted"
            deprecation = entry.get("deprecation")
            if deprecation:
                reasons = ", ".join(deprecation.get("reasons") or [])
                message = (deprecation.get("message") or "").strip()
                info["deprecated"][version] = (f"[{reasons}] " if reasons else "") + message
                alternate = deprecation.get("alternatePackage") or {}
                if alternate.get("id") and alternate["id"].lower() != ident:
                    info["alternate"] = alternate["id"]
                    info["alternates"][version] = alternate["id"]
                    rng = alternate.get("range") or ""
                    info["alternate_range"] = "" if rng in ("*", "") else rng
            if entry.get("published"):
                info["publish_dates"][version] = entry["published"]
                info["last_publish"] = max(info["last_publish"], entry["published"])
            if entry.get("projectUrl") and not info.get("repo_url"):
                info["repo_url"] = entry["projectUrl"]
    if not info["versions"]:
        flat = f"https://api.nuget.org/v3-flatcontainer/{urllib.parse.quote(ident)}/index.json"
        doc = http.cached_json(flat)
        if doc:
            info["versions"] = list(doc.get("versions") or [])
            info["source"] = flat
        else:
            info["error"] = "nuget registry lookup failed"
    info["display_name"] = info["display_name"] or purl.name
    if info["last_publish"].startswith("1900"):
        info["last_publish"] = ""
    return info


def pypi_registry(http, purl):
    info = empty_registry()
    url = f"https://pypi.org/pypi/{urllib.parse.quote(purl.name)}/json"
    info["source"] = url
    doc = http.cached_json(url)
    if not doc:
        info["error"] = "pypi lookup failed"
        return info
    meta = doc.get("info") or {}
    info["display_name"] = meta.get("name") or purl.name
    info["latest"] = meta.get("version")
    project_urls = meta.get("project_urls") or {}
    repo_url = ""
    for key, val in project_urls.items():
        if val and any(w in key.lower() for w in ("source", "repo", "code", "github", "gitlab")):
            repo_url = val
            break
    if not repo_url:
        for val in project_urls.values():
            if val and ("github.com" in val or "gitlab.com" in val):
                repo_url = val
                break
    info["repo_url"] = repo_url or meta.get("home_page") or ""
    releases = doc.get("releases") or {}
    info["versions"] = list(releases.keys())
    for version, files in releases.items():
        if files and all(f.get("yanked") for f in files):
            info["unusable"][version] = "yanked"
        if files:
            reason = next((f.get("yanked_reason") for f in files if f.get("yanked_reason")), "")
            if reason:
                info["deprecated"][version] = f"yanked: {reason}"
            stamps = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
            if stamps:
                info["publish_dates"][version] = min(stamps)
    urls = doc.get("urls") or []
    if urls and urls[0].get("upload_time_iso_8601"):
        info["last_publish"] = urls[0]["upload_time_iso_8601"]
    return info


def cpan_registry(http, purl):
    """MetaCPAN. purl names the distribution; any namespace is the CPAN author."""
    info = empty_registry()
    dist = purl.name
    url = ("https://fastapi.metacpan.org/v1/release/_search?"
           + urllib.parse.urlencode({
               "q": f'distribution:"{dist}"',
               "size": "300",
               "_source": "version,date,status",
           }))
    info["source"] = url
    doc = http.cached_json(url)
    hits = (((doc or {}).get("hits") or {}).get("hits") or []) if isinstance(doc, dict) else []
    if not hits:
        info["error"] = f"no CPAN distribution named {dist}"
        return info
    for hit in hits:
        src = hit.get("_source") or {}
        version, date, status = src.get("version"), src.get("date"), src.get("status")
        if not version:
            continue
        version = str(version)
        if version not in info["versions"]:
            info["versions"].append(version)
        if date:
            info["publish_dates"][version] = date
        # "backpan" means the author pulled it from the CPAN mirrors; it stays
        # archived but should never be an upgrade target
        if status == "backpan":
            info["unusable"][version] = "withdrawn from CPAN"
        elif status == "latest":
            info["latest"] = version
    if info["publish_dates"]:
        info["last_publish"] = max(info["publish_dates"].values())
    info["display_name"] = dist
    info["repo_url"] = f"https://metacpan.org/dist/{urllib.parse.quote(dist)}"
    return info


def maven_search_timestamps(http, group, artifact):
    """{version: iso date} from Maven Central's search index, or {} if it fails.

    maven-metadata.xml carries no per-version dates and omits lastUpdated on
    older artifacts; the search index has a publish timestamp on every row.
    """
    url = ("https://search.maven.org/solrsearch/select?"
           + urllib.parse.urlencode({
               "q": f'g:"{group}" AND a:"{artifact}"',
               "core": "gav", "rows": "200", "wt": "json",
           }))
    doc = http.cached_json(url)
    if not isinstance(doc, dict):
        return {}
    out = {}
    for row in ((doc.get("response") or {}).get("docs") or []):
        version, stamp = row.get("v"), row.get("timestamp")
        if not version or not stamp:
            continue
        try:
            out[version] = datetime.fromtimestamp(
                stamp / 1000, timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            continue
    return out


def maven_registry(http, purl):
    info = empty_registry()
    if not purl.namespace:
        info["error"] = "maven purl missing groupId"
        return info

    def parse(raw):
        root = ET.fromstring(raw)
        versions = [e.text for e in root.iter("version") if e.text]
        release = root.findtext("./versioning/release") or None
        updated = root.findtext("./versioning/lastUpdated") or ""
        return {"versions": versions, "release": release, "lastUpdated": updated}

    def metadata_url(group, artifact):
        path = group.replace(".", "/").replace("//", "/")
        return f"https://repo1.maven.org/maven2/{path}/{artifact}/maven-metadata.xml"

    # repo1 paths are case-sensitive and 404 on the wrong casing. Scanners that
    # infer coordinates rather than read them out of a POM routinely emit
    # upper-cased groupIds/artifactIds, so fall back to lowercase and keep
    # whichever casing actually resolved -- the registry link is built from it.
    attempts = [(purl.namespace, purl.name)]
    lowered = (purl.namespace.lower(), purl.name.lower())
    if lowered != attempts[0]:
        attempts.append(lowered)

    doc, group, artifact = None, purl.namespace, purl.name
    for group, artifact in attempts:
        url = metadata_url(group, artifact)
        info["source"] = url
        doc = http.cached_json(url, parser=parse)
        if doc:
            break
    if not doc:
        # get() retries real transport errors and only gives up quietly on
        # 404/410, so an exhausted lookup here almost always means the
        # coordinate simply isn't on Central -- vendor repos (Confluent,
        # Red Hat) and internal Artifactory-only artifacts land here.
        tried = " or ".join(f"{g}:{a}" for g, a in attempts)
        info["error"] = (f"not published on Maven Central as {tried} "
                         "(vendor or internal repository?)")
        return info
    info["resolved_namespace"] = group
    info["resolved_name"] = artifact
    if (group, artifact) != (purl.namespace, purl.name):
        info["notes"] = (f"resolved maven coordinates as {group}:{artifact}; "
                         f"the input purl's casing ({purl.namespace}:{purl.name}) "
                         "does not exist on Maven Central")
    info["versions"] = doc["versions"]
    info["latest"] = doc.get("release")
    info["last_publish"] = doc.get("lastUpdated") or ""
    if not info["last_publish"]:
        # Legacy artifacts predate the lastUpdated field and their metadata can
        # also be missing versions outright (jdom lists 1.0 but not 1.1). These
        # are exactly the decades-old packages an age check has to catch, so
        # fall back to the search index, which carries a timestamp per version.
        stamps = maven_search_timestamps(http, group, artifact)
        if stamps:
            info["publish_dates"].update(stamps)
            for version in stamps:
                if version not in info["versions"]:
                    info["versions"].append(version)
            info["last_publish"] = max(stamps.values())
    info["display_name"] = f"{group}:{artifact}"
    # Per-version publish dates and source-code links need a POM fetch per version
    # (maven-metadata.xml carries neither), which doesn't scale to a 30k-package
    # batch -- left as a known gap rather than a slow, half-reliable guess. Socket's
    # own publishedAt on the purl/alerts response (see analyze()) covers age for the
    # versions it has already ingested; source_code_link stays blank for maven here.
    return info


def golang_registry(http, purl):
    info = empty_registry()
    module = purl.full_name
    escaped = re.sub(r"([A-Z])", lambda m: "!" + m.group(1).lower(), module)
    list_url = f"https://proxy.golang.org/{escaped}/@v/list"
    info["source"] = list_url
    doc = http.cached_json(list_url, parser=lambda raw: raw.decode().split())
    if doc is None:
        info["error"] = "go module proxy lookup failed"
        return info
    info["versions"] = doc
    latest = http.cached_json(f"https://proxy.golang.org/{escaped}/@latest")
    if latest:
        info["latest"] = latest.get("Version")
        info["last_publish"] = latest.get("Time") or ""
        if latest.get("Version") and latest.get("Time"):
            info["publish_dates"][latest["Version"]] = latest["Time"]
    # One extra (cached) call for the input version's own publish date -- the
    # @v/list endpoint carries no dates, and this is what fills
    # input_version_age_days for golang rows.
    version = purl.version if purl.version in doc else ("v" + purl.version if "v" + purl.version in doc else "")
    if version and version not in info["publish_dates"]:
        meta = http.cached_json(f"https://proxy.golang.org/{escaped}/@v/{urllib.parse.quote(version)}.info")
        if meta and meta.get("Time"):
            info["publish_dates"][version] = meta["Time"]
    info["display_name"] = module
    if "." in module.split("/")[0]:
        info["repo_url"] = f"https://{module}"
    return info


def cargo_registry(http, purl):
    info = empty_registry()
    url = f"https://crates.io/api/v1/crates/{urllib.parse.quote(purl.name)}"
    info["source"] = url
    doc = http.cached_json(url)
    if not doc:
        info["error"] = "crates.io lookup failed"
        return info
    crate = doc.get("crate") or {}
    info["display_name"] = crate.get("id") or purl.name
    info["latest"] = crate.get("max_stable_version") or crate.get("max_version")
    info["last_publish"] = crate.get("updated_at") or ""
    info["repo_url"] = crate.get("repository") or ""
    for version in doc.get("versions") or []:
        num = version.get("num")
        if not num:
            continue
        info["versions"].append(num)
        if version.get("yanked"):
            info["unusable"][num] = "yanked"
        if version.get("created_at"):
            info["publish_dates"][num] = version["created_at"]
    return info


def gem_registry(http, purl):
    info = empty_registry()
    url = f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(purl.name)}.json"
    info["source"] = url
    doc = http.cached_json(url)
    if not doc:
        info["error"] = "rubygems lookup failed"
        return info
    for version in doc:
        num = version.get("number")
        if not num:
            continue
        info["versions"].append(num)
        if version.get("created_at"):
            info["publish_dates"][num] = version["created_at"]
    info["display_name"] = purl.name
    if doc:
        info["last_publish"] = doc[0].get("created_at") or ""
    gem_url = f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(purl.name)}.json"
    meta = http.cached_json(gem_url)
    if meta:
        info["repo_url"] = meta.get("source_code_uri") or meta.get("homepage_uri") or ""
    return info


def github_registry(http, purl):
    info = empty_registry()
    if not purl.namespace:
        info["error"] = "github purl missing owner"
        return info
    owner, repo = purl.namespace, purl.name
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    info["source"] = f"https://api.github.com/repos/{owner}/{repo}/tags"
    info["repo_url"] = f"https://github.com/{owner}/{repo}"
    tags = []
    for page in (1, 2, 3):
        url = f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=100&page={page}"
        doc = http.cached_json(url, headers=headers)
        if not doc:
            break
        tags.extend(t.get("name") for t in doc if t.get("name"))
        if len(doc) < 100:
            break
    info["versions"] = [t for t in tags if t]
    latest = http.cached_json(
        f"https://api.github.com/repos/{owner}/{repo}/releases/latest", headers=headers
    )
    if latest and latest.get("tag_name"):
        info["latest"] = latest["tag_name"]
        info["last_publish"] = latest.get("published_at") or ""
        info["publish_dates"][latest["tag_name"]] = latest.get("published_at") or ""
    if not info["versions"] and not info["latest"]:
        info["error"] = "github tag lookup failed"
    info["display_name"] = f"{owner}/{repo}"
    return info


def apk_registry(http, purl, branches, repos):
    """Newest apk version across the configured Alpine branches/repos via APKINDEX."""
    info = empty_registry()
    arch = purl.qualifiers.get("arch") or "x86_64"
    info["source"] = f"https://dl-cdn.alpinelinux.org/alpine/<branch>/<repo>/{arch}/APKINDEX.tar.gz"
    found = {}
    for branch in branches:
        for repo in repos:
            url = f"https://dl-cdn.alpinelinux.org/alpine/{branch}/{repo}/{arch}/APKINDEX.tar.gz"
            index = http.cached_json(url, parser=parse_apkindex)
            if not index:
                continue
            version = index.get(purl.name)
            if version:
                found[f"{branch}/{repo}"] = version
    if not found:
        info["error"] = f"package not found in APKINDEX for arch={arch}"
        return info
    info["versions"] = sorted(set(found.values()), key=lambda v: version_key("apk", v))
    info["latest"] = info["versions"][-1]
    info["display_name"] = purl.name
    info["notes"] = ", ".join(f"{k}={v}" for k, v in sorted(found.items()))
    return info


def parse_apkindex(raw):
    """Return {package name: version} from an APKINDEX.tar.gz payload."""
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        member = next((m for m in tar.getmembers() if m.name.endswith("APKINDEX")), None)
        if member is None:
            return None
        text = tar.extractfile(member).read().decode("utf-8", "replace")
    out, name = {}, None
    for line in text.splitlines():
        if line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:") and name:
            version = line[2:].strip()
            prior = out.get(name)
            if prior is None or version_key("apk", version) > version_key("apk", prior):
                out[name] = version
    return out


def lookup_registry(http, purl, opts):
    try:
        if purl.type == "npm":
            return npm_registry(http, purl)
        if purl.type == "nuget":
            return nuget_registry(http, purl)
        if purl.type == "pypi":
            return pypi_registry(http, purl)
        if purl.type == "maven":
            return maven_registry(http, purl)
        if purl.type == "golang":
            return golang_registry(http, purl)
        if purl.type == "cargo":
            return cargo_registry(http, purl)
        if purl.type == "gem":
            return gem_registry(http, purl)
        if purl.type == "github":
            return github_registry(http, purl)
        if purl.type == "apk":
            return apk_registry(http, purl, opts.alpine_branches, opts.alpine_repos)
        if purl.type == "cpan":
            return cpan_registry(http, purl)
    except Exception as err:  # noqa: BLE001 - never let one registry kill the run
        return empty_registry(error=f"{purl.type} lookup error: {err}")
    return empty_registry(error=f"no version source for ecosystem '{purl.type}'")


def replacement_lookup(http, eco, name, opts):
    """Resolve a replacement package name to its newest version, if we can."""
    fake = parse_purl(f"pkg:{eco}/{urllib.parse.quote(name, safe='@/')}@0")
    if fake is None:
        return "", ""
    info = lookup_registry(http, fake, opts)
    if info.get("error") and not info.get("versions"):
        return "", ""
    version = pick_newest(eco, info, opts)
    return info.get("display_name") or name, version or ""


# --------------------------------------------------------------------------- #
# replacement extraction from deprecation text
# --------------------------------------------------------------------------- #

_REPLACEMENT_PATTERNS = [
    r"use\s+(?:the\s+)?[`'\"]?([@\w][\w.@/-]{1,80}?)[`'\"]?\s+(?:package\s+)?instead",
    r"replaced\s+(?:by|with)\s+[`'\"]?([@\w][\w.@/-]{1,80}?)[`'\"]?\b",
    r"superseded\s+by\s+[`'\"]?([@\w][\w.@/-]{1,80}?)[`'\"]?\b",
    r"(?:migrate|switch|move|upgrade)\s+to\s+[`'\"]?([@\w][\w.@/-]{1,80}?)[`'\"]?\b",
    r"renamed\s+to\s+[`'\"]?([@\w][\w.@/-]{1,80}?)[`'\"]?\b",
    r"now\s+(?:published|available)\s+(?:as|at)\s+[`'\"]?([@\w][\w.@/-]{1,80}?)[`'\"]?\b",
    r"please\s+use\s+[`'\"]?([@\w][\w.@/-]{1,80}?)[`'\"]?\b",
]
_REPLACEMENT_STOPWORDS = {
    "this", "the", "it", "a", "an", "instead", "package", "packages", "version",
    "versions", "latest", "newer", "new", "current", "official", "supported",
    "https", "http", "github.com", "npm", "nuget", "node", "dotnet", "us", "our",
}


def extract_replacement(text, self_name):
    """Pull a replacement package name out of a deprecation message. Regex only."""
    if not text:
        return ""
    cleaned = re.sub(r"https?://\S+", " ", text)
    for pattern in _REPLACEMENT_PATTERNS:
        match = re.search(pattern, cleaned, re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1).strip(" .,;:'\"`()[]")
        low = candidate.lower()
        if not candidate or low in _REPLACEMENT_STOPWORDS:
            continue
        if low == (self_name or "").lower():
            continue
        if len(candidate) < 3 or not re.search(r"[A-Za-z]", candidate):
            continue
        if candidate.endswith((".", "-", "/")):
            candidate = candidate.rstrip("./-")
        return candidate
    return ""


# --------------------------------------------------------------------------- #
# socket purl api
# --------------------------------------------------------------------------- #

def basic_auth_header(token):
    return "Basic " + base64.b64encode((token + ":").encode()).decode()


def _alert_identity(alert):
    """Socket alerts carry a stable per-instance `key`; fall back to the whole
    object for the rare alert without one."""
    return alert.get("key") or json.dumps(alert, sort_keys=True)


def _merge_alerts(*alert_lists):
    seen, out = set(), []
    for alerts in alert_lists:
        for alert in alerts:
            ident = _alert_identity(alert)
            if ident in seen:
                continue
            seen.add(ident)
            out.append(alert)
    return out


class Socket:
    def __init__(self, token, org, batch_size=250, timeout=300, threads=4, verbose=False):
        self.auth = basic_auth_header(token)
        # Org-scoped endpoint: POST /v0/purl (no org) was deprecated 2026-01-05 and
        # its removal date (2026-07-30) has already passed. This is the successor --
        # same request/response shape, plus repo-label policy scoping via `labels=`.
        self.purl_url = f"{SOCKET_API_BASE}/orgs/{urllib.parse.quote(org)}/purl"
        self.org = org
        self.batch_size = batch_size
        self.timeout = timeout
        self.threads = max(1, threads)
        self.verbose = verbose
        self.cache = {}
        self.requests = 0
        self.fatal = None  # "HTTP 403 ..." once auth/permissions are known-broken
        self.lock = threading.Lock()

    def _post(self, purls):
        body = json.dumps({"components": [{"purl": p} for p in purls]}).encode()
        req = urllib.request.Request(
            self.purl_url + "?alerts=true",
            data=body,
            headers={
                "Authorization": self.auth,
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        with self.lock:
            self.requests += 1
        records = []
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            for line in resp:
                line = line.strip()
                if line and line != b'"':
                    try:
                        records.append(json.loads(line))
                    except ValueError:
                        continue
        return records

    def _fetch(self, purls, attempt=1):
        if self.fatal:
            return []
        try:
            return self._post(purls)
        except urllib.error.HTTPError as err:
            if err.code in (401, 403, 404):
                # Auth, permissions, or a wrong org slug: no amount of retrying
                # or batch-splitting fixes these. Fail the Socket stage once,
                # loudly, and let the registry-only report proceed.
                detail = ""
                try:
                    detail = err.read()[:200].decode("utf-8", "replace").strip()
                except OSError:
                    pass
                hint = {
                    401: "check SOCKET_API_KEY",
                    403: "token lacks the packages:list scope for this org",
                    404: f"org '{self.org}' not found for this token",
                }[err.code]
                with self.lock:
                    if not self.fatal:
                        self.fatal = f"HTTP {err.code} from the Socket purl API ({hint})"
                        print(f"  Socket purl API: {self.fatal}"
                              + (f" -- {detail}" if detail else ""), file=sys.stderr)
                        print("  continuing with registry data only; Socket columns will be blank",
                              file=sys.stderr)
                return []
            return self._retry(purls, attempt, err)
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            return self._retry(purls, attempt, err)

    def _retry(self, purls, attempt, err):
        if attempt < 3:
            wait = 2 ** attempt
            print(f"  batch of {len(purls)} failed ({err}); retry in {wait}s", file=sys.stderr)
            time.sleep(wait)
            return self._fetch(purls, attempt + 1)
        if len(purls) > 1:
            mid = len(purls) // 2
            return self._fetch(purls[:mid]) + self._fetch(purls[mid:])
        print(f"  giving up on {purls[0]}: {err}", file=sys.stderr)
        return []

    def _absorb(self, chunk, records):
        with self.lock:
            for record in records:
                key = record.get("inputPurl")
                if not key:
                    continue
                prior = self.cache.get(key)
                if prior is None:
                    self.cache[key] = record
                else:
                    # The purl endpoint returns one record per stored artifact
                    # (a pypi package with 12 wheels + an sdist returns 13
                    # records, verified live), each repeating mostly the same
                    # alerts. Union them by the alert's own identity key so a
                    # package's alert list isn't counted once per wheel.
                    merged = dict(prior)
                    merged["alerts"] = _merge_alerts(prior.get("alerts") or [],
                                                     record.get("alerts") or [])
                    self.cache[key] = merged
            for purl in chunk:
                self.cache.setdefault(purl, None)

    def query(self, purls):
        """Populate the record cache for every purl not already known."""
        if self.fatal:
            return self.cache
        todo = [p for p in dict.fromkeys(purls) if p not in self.cache]
        chunks = [todo[i:i + self.batch_size] for i in range(0, len(todo), self.batch_size)]
        if not chunks:
            return self.cache
        with ThreadPoolExecutor(max_workers=min(self.threads, len(chunks))) as pool:
            for chunk, records in zip(chunks, pool.map(self._fetch, chunks)):
                self._absorb(chunk, records)
        return self.cache


def alert_detail(alert):
    props = alert.get("props") or {}
    for key in ("cveId", "ghsaId", "reason", "lastPublish", "note", "notes", "envVars",
                "module", "urls", "license", "score", "id"):
        if props.get(key):
            value = props[key]
            if isinstance(value, (list, dict)):
                value = json.dumps(value)
            return f"{key}={value}"[:300]
    return ""


RISK_CATEGORIES = {"vulnerability", "malware"}
RISK_SEVERITIES = {"high", "critical"}
# Socket has no verdict yet for these; never call such a version safe.
UNKNOWN_ALERT_TYPES = {"notFound", "pendingScan"}


def make_actionable(opts):
    """Predicate deciding which alerts disqualify a version. Pure config, no judgement."""
    if opts.safe_mode == "strict":
        return lambda alert: True
    if opts.safe_mode == "severity":
        return lambda alert: (
            (alert.get("severity") or "") in RISK_SEVERITIES
            or (alert.get("category") or "") in RISK_CATEGORIES
            or (alert.get("type") or "") in ("malware", "deprecated", "unmaintained")
        )
    actions = opts.actionable_actions
    return lambda alert: (alert.get("action") or "") in actions


def classify(record, actionable):
    """clean | dirty | unknown for one Socket record."""
    if record is None:
        return "unknown", []
    alerts = record.get("alerts") or []
    types = {a.get("type") for a in alerts}
    if types & UNKNOWN_ALERT_TYPES:
        return "unknown", alerts
    hits = [a for a in alerts if actionable(a)]
    return ("dirty" if hits else "clean"), alerts


# --------------------------------------------------------------------------- #
# socket fixes api (dependency-graph-aware, CVE-targeted upgrade planning)
# --------------------------------------------------------------------------- #

def synthesize_manifest(eco, purls):
    """Build a minimal, exact-pinned manifest so the Fixes API resolves against
    these exact input versions. Returns (filename, content), or (None, None)
    if this ecosystem isn't wired up for synthesis."""
    pinned = [p for p in purls if p.version]
    if not pinned:
        return None, None
    if eco == "npm":
        deps = {p.full_name: p.version for p in pinned}
        content = json.dumps(
            {"name": "socket-fixes-probe", "version": "0.0.0", "private": True, "dependencies": deps},
            indent=2,
        )
        return "package.json", content
    if eco == "pypi":
        lines = [f"{p.full_name}=={p.version}" for p in pinned]
        return "requirements.txt", "\n".join(lines) + "\n"
    if eco == "maven":
        deps_xml = "\n".join(
            f"    <dependency>\n      <groupId>{p.namespace}</groupId>\n"
            f"      <artifactId>{p.name}</artifactId>\n      <version>{p.version}</version>\n    </dependency>"
            for p in pinned
        )
        content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>dev.socket.probe</groupId>\n"
            "  <artifactId>socket-fixes-probe</artifactId>\n"
            "  <version>0.0.0</version>\n"
            "  <dependencies>\n" + deps_xml + "\n  </dependencies>\n"
            "</project>\n"
        )
        return "pom.xml", content
    return None, None


def _multipart_encode(fields):
    """fields: [(name, content)]. Plain form fields -- NO filename= attribute.

    Verified live: sending a manifest as a file part (curl's -F name=@file, or a
    Content-Disposition with filename=) makes the server store empty bytes for
    that part. The field NAME must be the manifest's path (e.g. "package.json")
    and the VALUE must be the raw text content, as a plain form field.
    """
    boundary = "socketfixes" + hashlib.sha1(os.urandom(16)).hexdigest()
    body = bytearray()
    for name, content in fields:
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += content.encode() if isinstance(content, str) else content
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def upload_manifest_files(org, token, manifests, timeout=120):
    """POST /v0/orgs/{org}/upload-manifest-files -> tarHash, or None on failure.

    Best-effort: this is an enhancement layer on top of the core upgrade plan,
    never a hard dependency, so every failure just prints a warning and the
    caller moves on with fixes_api_* columns left blank.
    """
    body, content_type = _multipart_encode(manifests)
    url = f"{SOCKET_API_BASE}/orgs/{urllib.parse.quote(org)}/upload-manifest-files"
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Authorization": basic_auth_header(token), "Content-Type": content_type,
                 "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read())
    except urllib.error.HTTPError as err:
        scope_hint = (" -- token likely lacks the full-scans:create scope"
                      if err.code in (401, 403) else "")
        print(f"  fixes API: upload-manifest-files failed (HTTP {err.code}{scope_hint}); "
              "skipping this Fixes API call", file=sys.stderr)
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as err:
        print(f"  fixes API: upload-manifest-files failed ({err}); "
              "skipping this Fixes API call", file=sys.stderr)
        return None
    unmatched = doc.get("unmatchedFiles") or []
    if unmatched:
        print(f"  fixes API: {len(unmatched)} manifest file(s) did not resolve: {unmatched}",
              file=sys.stderr)
    return doc.get("tarHash")


def fetch_fixes(org, token, tar_hash, min_release_age="0d", allow_major_updates=True, timeout=120):
    """GET /v0/orgs/{org}/fixes?tar_hash=...&vulnerability_ids=* -> the raw
    fixDetails dict (keyed by GHSA), or {} on any failure."""
    params = {
        "tar_hash": tar_hash,
        "vulnerability_ids": "*",
        "include_details": "true",
        "minimum_release_age": min_release_age,
        "allow_major_updates": "true" if allow_major_updates else "false",
    }
    url = f"{SOCKET_API_BASE}/orgs/{urllib.parse.quote(org)}/fixes?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": basic_auth_header(token),
                                                "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read())
    except urllib.error.HTTPError as err:
        scope_hint = (" -- token likely lacks the fixes:list scope"
                      if err.code in (401, 403) else "")
        print(f"  fixes API: /fixes lookup failed (HTTP {err.code}{scope_hint})", file=sys.stderr)
        return {}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as err:
        print(f"  fixes API: /fixes lookup failed ({err})", file=sys.stderr)
        return {}
    return doc.get("fixDetails") or {}


def cross_reference_fixes(rows, org, token, min_release_age, allow_major_updates):
    """rows: purls already known to carry >=1 GHSA-bearing alert, in an
    ecosystem the Fixes API cross-reference supports. Returns
    {(ecosystem, full_name, version): {fixed_version, update_type, ghsas, kev,
    max_epss}} -- keyed by the exact package version the fix applies to (the
    /fixes response echoes the pinned input version on every fix's purl), so a
    fix never leaks onto a different, possibly clean, version of the same
    package elsewhere in the input.
    """
    by_eco = {}
    for row in rows:
        p = row.purl
        if p.version:
            by_eco.setdefault(p.type, {})[(p.full_name, p.version)] = p

    results = {}
    for eco, unique in by_eco.items():
        # A manifest can pin only one version per package name -- and the maven
        # resolver silently keeps just one of two duplicate declarations
        # (verified live) -- so same-name different-version inputs go in
        # separate calls. On top of that, the graph resolution behind /fixes
        # times out on very large single manifests (measured: fine at 40
        # packages, dead at 200), so each call carries at most FIXES_CHUNK.
        by_name = {}
        for (name, version), p in sorted(unique.items(),
                                          key=lambda kv: (kv[0][0], version_key(eco, kv[0][1]))):
            by_name.setdefault(name, []).append(p)
        chunks = []
        depth = 0
        while True:
            wave = [versions[depth] for versions in by_name.values() if depth < len(versions)]
            if not wave:
                break
            chunks.extend(wave[i:i + FIXES_CHUNK] for i in range(0, len(wave), FIXES_CHUNK))
            depth += 1
        print(f"  fixes API: probing {len(unique)} {eco} package(s) with known CVEs "
              f"in {len(chunks)} call(s) ...")
        for number, chunk in enumerate(chunks, 1):
            filename, content = synthesize_manifest(eco, chunk)
            if not filename:
                continue
            if len(chunks) > 1:
                print(f"    fixes API: {eco} call {number}/{len(chunks)} ({len(chunk)} packages)")
            tar_hash = upload_manifest_files(org, token, [(filename, content)])
            if not tar_hash:
                continue
            fix_details = fetch_fixes(org, token, tar_hash, min_release_age,
                                      allow_major_updates, timeout=300)
            _merge_fix_details(eco, fix_details, results)
    return results


def _epss_score(epss):
    """advisoryDetails.epss is a plain float on the live response (verified:
    0.00792 on GHSA-rhx6-c78j-4q9w); tolerate the {"score": ...} object shape
    too rather than silently dropping the value."""
    if isinstance(epss, (int, float)) and not isinstance(epss, bool):
        return epss
    if isinstance(epss, dict):
        return epss.get("score")
    return None


def _merge_fix_details(eco, fix_details, results):
    for ghsa, variant in fix_details.items():
        value = variant.get("value") or {}
        fixes = ((value.get("fixDetails") or {}).get("fixes")) or []
        advisory = value.get("advisoryDetails") or {}
        kev = bool(advisory.get("kev"))
        epss = _epss_score(advisory.get("epss"))
        for fix in fixes:
            purl_str = fix.get("purl") or ""
            fixed_version = fix.get("fixedVersion")
            if not purl_str or not fixed_version:
                continue
            parsed = parse_purl(purl_str)
            if not parsed:
                continue
            key = (eco, parsed.full_name, parsed.version)
            entry = results.get(key)
            if entry is None:
                entry = {"fixed_version": fixed_version, "update_type": fix.get("updateType") or "",
                          "ghsas": [], "kev": False, "max_epss": None}
                results[key] = entry
            elif version_key(eco, fixed_version) > version_key(eco, entry["fixed_version"]):
                entry["fixed_version"] = fixed_version
                entry["update_type"] = fix.get("updateType") or entry["update_type"]
            if ghsa not in entry["ghsas"]:
                entry["ghsas"].append(ghsa)
            entry["kev"] = entry["kev"] or kev
            if epss is not None:
                entry["max_epss"] = max(entry["max_epss"] or 0.0, epss)


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #

class Row:
    def __init__(self, raw, purl):
        self.raw = raw
        self.purl = purl
        self.registry = empty_registry()
        self.newest = None
        self.candidates = []
        self.cursor = 0
        self.chunk = []
        self.probed = 0
        self.unknown_versions = []
        self.dirty_versions = []
        self.safe = None
        self.notes = []


def pick_newest(eco, info, opts, input_version=None):
    versions = info.get("versions") or []
    unusable = info.get("unusable") or {}
    usable = [v for v in versions if v not in unusable]
    if not opts.include_prerelease:
        stable = [v for v in usable if not is_prerelease(eco, v)]
        if stable:
            usable = stable
    # Stay inside the input's release stream. Without an input version, the
    # mainline is the only defensible default: a bare package lookup shouldn't
    # answer with somebody's vendor build.
    target = release_stream(eco, input_version) if input_version else ""
    in_stream = [v for v in usable if release_stream(eco, v) == target]
    if not in_stream and target:
        # the input's stream isn't carried by this registry -- fall back to the
        # mainline rather than to whatever sorts highest across all streams
        in_stream = [v for v in usable if not release_stream(eco, v)]
    if in_stream:
        usable = in_stream
    # the registry's own "latest" pointer only counts if it's in the same stream
    latest = info.get("latest")
    effective = release_stream(eco, usable[0]) if in_stream and usable else target
    if latest and release_stream(eco, latest) != effective:
        latest = None
    if latest and (opts.include_prerelease or not is_prerelease(eco, latest)) and latest not in unusable:
        # registry-declared latest wins when it is not older than the newest we saw
        best = newest(eco, usable)
        if best is None or version_key(eco, latest) >= version_key(eco, best):
            return latest
        return best
    return newest(eco, usable) or latest or newest(eco, versions)


def build_candidates(row, opts):
    """Versions to probe for a safe version, newest first, input version included."""
    eco = row.purl.type
    info = row.registry
    unusable = info.get("unusable") or {}
    input_version = row.purl.version
    input_key = version_key(eco, input_version) if input_version else None
    target_stream = release_stream(eco, input_version) if input_version else ""
    pool = set()
    for version in info.get("versions") or []:
        if version in unusable:
            continue
        if not opts.include_prerelease and is_prerelease(eco, version) and version != input_version:
            continue
        # never probe across release streams (see release_stream)
        if version != input_version and release_stream(eco, version) != target_stream:
            continue
        if input_key and version_key(eco, version) < input_key:
            continue
        pool.add(version)
    if row.newest:
        pool.add(row.newest)
    if input_version:
        pool.add(input_version)
    ordered = sorted(pool, key=lambda v: version_key(eco, v), reverse=True)
    return ordered[: opts.max_candidates]


def probe_safe_versions(rows, socket, opts):
    pending = [r for r in rows if r.candidates]
    round_no = 0
    while pending:
        round_no += 1
        batch = []
        for row in pending:
            row.chunk = row.candidates[row.cursor:row.cursor + opts.probe_chunk]
            batch.extend(row.purl.socket_purl(v) for v in row.chunk)
        print(f"  probe round {round_no}: {len(pending)} packages, {len(batch)} purls")
        socket.query(batch)
        still = []
        for row in pending:
            for version in row.chunk:
                verdict, _ = classify(
                    socket.cache.get(row.purl.socket_purl(version)), opts.actionable
                )
                if verdict == "unknown":
                    row.unknown_versions.append(version)
                    continue
                if verdict == "clean":
                    row.safe = version
                    break
                row.dirty_versions.append(version)
            row.cursor += len(row.chunk)
            row.probed += len(row.chunk)
            if row.safe is None and row.cursor < len(row.candidates):
                still.append(row)
        pending = still


def analyze(row, http, socket, opts, fixes_by_key):
    eco = row.purl.type
    purl = row.purl
    info = row.registry
    input_purl = purl.with_version(purl.version) if purl.version else purl.raw
    record = socket.cache.get(purl.socket_purl(purl.version))
    _, alerts = classify(record, opts.actionable)
    alert_types = sorted({a.get("type") for a in alerts if a.get("type")})
    actionable = [a for a in alerts if opts.actionable(a)]
    socket_found = record is not None and "notFound" not in set(alert_types)
    scan_pending = "pendingScan" in set(alert_types)
    max_sev = ""
    if alerts:
        max_sev = max((a.get("severity") or "" for a in alerts),
                      key=lambda sev: SEVERITY_RANK.get(sev, 0))

    ghsa_ids = sorted({(a.get("props") or {}).get("ghsaId")
                        for a in alerts if (a.get("props") or {}).get("ghsaId")})

    score = (record or {}).get("score") or {}

    def pct(key):
        value = score.get(key)
        return round(value * 100) if isinstance(value, (int, float)) else ""

    newest_version = row.newest or ""
    safe_version = row.safe or ""

    # deprecation: the input version and the package (newest release) are separate facts
    socket_deprecated = next((a for a in alerts if a.get("type") == "deprecated"), None)
    input_note = info["deprecated"].get(purl.version, "")
    if not input_note and socket_deprecated:
        input_note = (socket_deprecated.get("props") or {}).get("reason", "") or "deprecated"
    newest_note = info["deprecated"].get(newest_version, "") if newest_version else ""
    input_deprecated = bool(input_note)
    package_deprecated = bool(newest_note)
    deprecation_reason = newest_note or input_note

    unmaintained = next((a for a in alerts if a.get("type") == "unmaintained"), None)
    last_publish = ""
    if unmaintained:
        last_publish = (unmaintained.get("props") or {}).get("lastPublish", "") or ""
    last_publish = last_publish or info.get("last_publish") or ""

    # Package/version age: prefer Socket's own publishedAt (on the purl/alerts
    # response already fetched above -- no extra call), fall back to the
    # per-version publish date the registry lookup already captured. Socket's
    # field is sparsely backfilled for artifacts ingested before it existed,
    # which is exactly when the registry fallback fires.
    socket_published_at = (record or {}).get("publishedAt") or ""
    registry_published_at = info.get("publish_dates", {}).get(purl.version, "") if purl.version else ""
    input_version_published_at = socket_published_at or registry_published_at or ""
    age_source = "socket" if socket_published_at else ("registry" if registry_published_at else "")
    input_version_age_days = ""
    if input_version_published_at:
        try:
            input_version_age_days = (datetime.now(timezone.utc) - _parse_iso(input_version_published_at)).days
        except Exception:
            input_version_age_days = ""

    # How long since the package last shipped anything. A version can carry no
    # alerts and still be a bad recommendation because nobody has touched it in
    # a decade, and Socket's unmaintained alert doesn't fire on every such
    # package. Prefer the newest version's own date, fall back to the
    # package-level last publish. No date means no claim either way.
    newest_published_at = (info.get("publish_dates", {}).get(newest_version, "")
                           if newest_version else "")
    package_release_date = newest_published_at or last_publish
    package_last_release_days = ""
    if package_release_date:
        try:
            package_last_release_days = (
                datetime.now(timezone.utc) - _parse_iso(package_release_date)).days
        except Exception:
            package_last_release_days = ""
    stale_package = bool(
        isinstance(package_last_release_days, int)
        and package_last_release_days > opts.stale_years * 365.25
    )

    # Scanner-emitted purls often differ from the registry's spelling only by
    # case (2.0B4 vs 2.0b4), so compare parsed keys rather than raw strings
    # before claiming a version is missing upstream.
    listed_versions = info.get("versions") or []
    input_listed = bool(purl.version) and any(
        version_key(eco, purl.version) == version_key(eco, v) for v in listed_versions
    )

    registry_url = registry_link(purl, info)
    # a deep link to a version the registry doesn't carry renders an empty page;
    # fall back to the package page, which does exist
    if purl.version and listed_versions and not input_listed \
            and eco not in ("apk", "github"):
        registry_url = registry_link(purl.without_version(), info) or registry_url
    source_code_link = info.get("repo_url") or ""
    if not source_code_link and eco == "github" and purl.namespace:
        source_code_link = f"https://github.com/{purl.full_name}"

    # a replacement package only matters when the newest release is itself dead
    replacement, replacement_source, replacement_version = "", "", ""
    if package_deprecated:
        alternate = info["alternates"].get(newest_version) or info.get("alternate")
        if alternate:
            replacement = alternate
            replacement_source = f"{eco} registry deprecation metadata"
        else:
            guess = extract_replacement(newest_note, purl.full_name)
            if guess:
                replacement = guess
                replacement_source = "parsed from deprecation notice"
    if replacement:
        resolved, replacement_version = replacement_lookup(http, eco, replacement, opts)
        if resolved:
            replacement = resolved
            replacement_source += " (verified in registry)"
        else:
            replacement_source += " (unverified)"

    # Version numbers only mean anything within one release stream, so an input
    # on a stream the registry doesn't carry is not comparable to its newest.
    comparable = bool(
        newest_version and purl.version and same_stream(eco, purl.version, newest_version)
    )
    cross_stream_only = bool(newest_version and purl.version and not comparable)
    input_is_newest = bool(
        comparable and version_key(eco, purl.version) >= version_key(eco, newest_version)
    )

    if info.get("error"):
        row.notes.append(info["error"])
    # apk indexes only current branches and the github client only pages the
    # newest 300 tags, so absence there proves nothing; every other registry
    # client returns the complete version list.
    input_stream = release_stream(eco, purl.version) if purl.version else ""
    # Only worth flagging when an excluded stream would otherwise have won the
    # recommendation. Packages carry stray one-off tags (rails has a lone
    # 5.0.0.racecar1) that are correctly skipped but not worth a line of report.
    newest_key = version_key(eco, newest_version) if newest_version else None
    other_streams = sorted({
        release_stream(eco, v) for v in (info.get("versions") or [])
        if release_stream(eco, v) and release_stream(eco, v) != input_stream
        and (newest_key is None or version_key(eco, v) > newest_key)
    })
    if other_streams:
        # name the newest of each excluded stream: without it the row says a
        # stream was skipped but leaves the reader no way to act on that
        tips = []
        for stream in other_streams:
            members = [v for v in (info.get("versions") or [])
                       if release_stream(eco, v) == stream]
            tip = newest(eco, members)
            tips.append(f"{stream} (newest {tip})" if tip else stream)
        row.notes.append(
            "excluded parallel release stream(s) " + ", ".join(tips)
            + f"; recommendations stay in the {input_stream or 'mainline'} stream, "
            "whose version numbers are not comparable to the others"
        )
    if newest_version and not opts.include_prerelease and is_prerelease(eco, newest_version):
        # the stable-only filter fell back because there is nothing stable to
        # pick; flag it rather than quietly handing back a prerelease
        row.notes.append(
            f"{newest_version} is a prerelease and is still the recommendation because this "
            "package publishes no stable release under that naming; treat it as a prerelease"
        )
    if purl.version and listed_versions and not input_listed \
            and eco not in ("apk", "github"):
        if input_stream:
            row.notes.append(
                f"input version {purl.version} is on the '{input_stream}' stream, which this "
                "registry does not publish; it likely comes from a vendor or internal "
                "repository, so treat the version data here as mainline-only"
            )
        else:
            row.notes.append(f"input version {purl.version} not published upstream "
                             "(typo or private build?)")
    if newest_version and newest_version in (info.get("unusable") or {}):
        row.notes.append(
            f"newest release {newest_version} is {info['unusable'][newest_version]} upstream "
            "(no listed versions remain)"
        )
    if info.get("notes"):
        row.notes.append(info["notes"])
    if not socket_found:
        if eco not in SOCKET_ANALYZED_ECOSYSTEMS:
            # "no alert data" on an ecosystem Socket doesn't analyze reads as
            # "checked and clean", which is the opposite of the truth
            row.notes.append(
                f"Socket does not analyze {eco} packages, so this row is registry metadata "
                "only: version and age are upstream facts, and the absence of alerts is not "
                "a security finding"
            )
        else:
            row.notes.append(socket.fatal or "no Socket analysis for this purl (notFound)")
    if scan_pending:
        row.notes.append("Socket scan still running (pendingScan); re-run for final alerts")
    if row.unknown_versions:
        row.notes.append("no Socket data for probed version(s): "
                         + ", ".join(row.unknown_versions[:5]))
    if unmaintained:
        row.notes.append(f"Socket unmaintained alert (last publish {last_publish or 'unknown'})")
    if input_deprecated:
        row.notes.append(f"input version {purl.version} deprecated upstream")
    if package_deprecated:
        row.notes.append(f"newest release {newest_version} also deprecated (package is dead)")

    fx = fixes_by_key.get((eco, purl.full_name, purl.version))
    fixes_api_version = fx["fixed_version"] if fx else ""
    fixes_api_update_type = fx["update_type"] if fx else ""
    fixes_api_kev = "TRUE" if fx and fx.get("kev") else ("FALSE" if fx else "")
    fixes_api_max_epss = fx.get("max_epss") if fx else ""
    fixes_api_note = ""
    if fx and safe_version and version_key(eco, fx["fixed_version"]) != version_key(eco, safe_version):
        fixes_api_note = (
            f"Fixes API suggests {fx['fixed_version']}; the simple per-version alert probe found "
            f"{safe_version} as the first clean version -- Fixes API accounts for transitive fixes "
            "and dependency-graph impact, so prefer its answer"
        )
        row.notes.append(fixes_api_note)

    # recommendation priority: replacement package (dead upstream, don't just
    # patch it) > Fixes API (graph-aware, CVE-targeted, most precise) >
    # newest safe version (brute-force probe) > newest version
    if replacement:
        rec_type = "replace_package"
        target = replacement + (f" {replacement_version}" if replacement_version else "")
        recommendation = f"Replace with {target} (this package is deprecated upstream)"
        recommended_purl = build_replacement_purl(eco, replacement, replacement_version)
    elif fx and fx.get("fixed_version"):
        rec_type = "upgrade_fixes_api"
        kev_note = " -- CISA Known Exploited Vulnerability" if fx.get("kev") else ""
        recommendation = (
            f"Upgrade to {fx['fixed_version']} ({fx['update_type'] or 'unknown'} bump; Socket Fixes "
            f"API resolves {', '.join(fx['ghsas'])}{kev_note})"
        )
        recommended_purl = purl.with_version(fx["fixed_version"])
    elif cross_stream_only:
        # The registry carries a different distribution stream than the input.
        # Naming its newest version here would be a cross-stream jump, so report
        # what Socket knows about the pinned version and stop short of a target.
        rec_type = "review_release_stream"
        stream = release_stream(eco, purl.version) or "vendor"
        if actionable:
            recommendation = (
                f"Review with your vendor: {purl.version} carries {opts.alert_label}, and the "
                f"'{stream}' stream it belongs to is not published in this registry, so a fixed "
                f"version in that stream has to come from the vendor. Mainline releases "
                f"(newest {newest_version}) use a separate numbering line and are not a "
                "drop-in upgrade"
            )
        else:
            recommendation = (
                f"No upgrade target: {purl.version} is on the '{stream}' stream, which this "
                f"registry does not publish, so its newest version is unknown here. Mainline "
                f"releases (newest {newest_version}) are numbered separately and are not a "
                "drop-in upgrade"
            )
        recommended_purl = ""
    elif safe_version and newest_version and \
            version_key(eco, safe_version) >= version_key(eco, newest_version):
        if purl.version and version_key(eco, safe_version) == version_key(eco, purl.version):
            rec_type = "stay_current"
            recommendation = f"Stay on {purl.version} (newest release and {opts.safe_label})"
        else:
            rec_type = "upgrade_newest_safe"
            recommendation = f"Upgrade to {safe_version} (newest release and {opts.safe_label})"
        recommended_purl = purl.with_version(safe_version)
    elif safe_version:
        if purl.version and version_key(eco, safe_version) == version_key(eco, purl.version):
            rec_type = "stay_current"
            recommendation = (
                f"Stay on {purl.version} ({opts.safe_label}); newer releases up to "
                f"{newest_version or 'unknown'} carry {opts.alert_label}"
            )
        else:
            rec_type = "upgrade_safe"
            recommendation = (
                f"Upgrade to {safe_version} (newest version with {opts.safe_label}); "
                f"newest release {newest_version or 'unknown'} carries {opts.alert_label}"
            )
        recommended_purl = purl.with_version(safe_version)
    elif newest_version and not input_is_newest:
        rec_type = "upgrade_newest"
        if row.dirty_versions:
            why = (f"none of the {row.probed} version(s) probed were free of {opts.alert_label}")
        else:
            why = f"Socket has no alert data for the {row.probed} version(s) probed"
        recommendation = f"Upgrade to {newest_version} (newest release; {why})"
        recommended_purl = purl.with_version(newest_version)
    elif newest_version:
        rec_type = "no_upgrade_available"
        if actionable and row.dirty_versions:
            recommendation = (f"Already on newest release ({newest_version}); no version free of "
                              f"{opts.alert_label} found")
        else:
            recommendation = f"Already on newest release ({newest_version})"
        recommended_purl = input_purl
    else:
        rec_type = "unknown"
        recommendation = "No registry version data; review manually"
        recommended_purl = ""

    if not replacement and (package_deprecated or unmaintained):
        state = "deprecated" if package_deprecated else "unmaintained"
        recommendation += (
            f" - package is {state} upstream and no replacement is published; plan a migration"
        )
        if rec_type != "unknown":
            rec_type = f"{rec_type}_{state}"
    elif input_deprecated and not package_deprecated:
        recommendation += f" - input version {purl.version} is deprecated upstream"

    # An alert-clean version of a package nobody has released in years is not a
    # clean bill of health. Say it on the recommendation, not just in a column,
    # unless the deprecated/unmaintained wording above already covers it.
    if stale_package and not (package_deprecated or unmaintained or replacement):
        years = package_last_release_days / 365.25
        recommendation += (
            f" - caution: no release in {years:.1f} years "
            f"(last {package_release_date[:10]}), so verify the package is still maintained"
        )
        if rec_type not in ("unknown", "review_release_stream"):
            rec_type = f"{rec_type}_stale"

    plan = {
        "input_purl": row.raw,
        "newest_version": newest_version,
        "safe_version": safe_version,
        "fixes_api_version": fixes_api_version,
        "recommendation": recommendation,
        "recommendation_type": rec_type,
        "recommended_purl": recommended_purl,
        "ecosystem": eco,
        "package_name": info.get("display_name") or purl.full_name,
        "registry_link": registry_url,
        "source_code_link": source_code_link,
        "input_version": purl.version,
        "input_is_newest": "TRUE" if input_is_newest else "FALSE",
        "socket_found": "TRUE" if socket_found else "FALSE",
        "input_alert_count": len(alerts) if socket_found else 0,
        "input_actionable_alert_count": len(actionable),
        "input_max_severity": max_sev if socket_found else "",
        "input_alert_types": "; ".join(t for t in alert_types if t != "notFound"),
        "input_ghsas": "; ".join(ghsa_ids),
        "fixes_api_update_type": fixes_api_update_type,
        "fixes_api_kev": fixes_api_kev,
        "fixes_api_max_epss": fixes_api_max_epss,
        "fixes_api_note": fixes_api_note,
        "socket_overall_score": pct("overall"),
        "socket_supply_chain_score": pct("supplyChain"),
        "socket_quality_score": pct("quality"),
        "socket_maintenance_score": pct("maintenance"),
        "socket_vulnerability_score": pct("vulnerability"),
        "socket_license_score": pct("license"),
        "input_version_deprecated": "TRUE" if input_deprecated else "FALSE",
        "package_deprecated": "TRUE" if package_deprecated else "FALSE",
        "is_unmaintained": "TRUE" if unmaintained else "FALSE",
        "input_version_published_at": input_version_published_at,
        "input_version_age_days": input_version_age_days,
        "age_source": age_source,
        "last_publish": last_publish,
        "package_last_release_days": package_last_release_days,
        "stale_package": "TRUE" if stale_package else "FALSE",
        "deprecation_reason": (deprecation_reason or "")[:500],
        "replacement_package": replacement,
        "replacement_newest_version": replacement_version,
        "replacement_source": replacement_source,
        "versions_probed": row.probed,
        "notes": "; ".join(dict.fromkeys(row.notes)),
    }
    return plan, alerts, socket_found


def build_replacement_purl(eco, name, version):
    if not version:
        return ""
    fake = parse_purl(f"pkg:{eco}/{urllib.parse.quote(name, safe='@/')}@0")
    return fake.with_version(version) if fake else ""


# --------------------------------------------------------------------------- #
# input / output
# --------------------------------------------------------------------------- #

def load_inputs(path, column=None):
    raws = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        if "," in sample or ";" in sample or "\t" in sample:
            reader = csv.reader(fh)
            rows = list(reader)
        else:
            rows = [[line.strip()] for line in fh if line.strip()]
    if not rows:
        return [], []
    header = rows[0]
    index = 0
    body = rows
    header_is_purl = any(cell.strip().lower().startswith("pkg:") for cell in header)
    looks_like_header = len(header) > 1 or any(
        word in cell.lower() for cell in header for word in ("purl", "package", "component")
    )
    if not header_is_purl and looks_like_header:
        body = rows[1:]
        if column:
            lowered = [h.strip().lower() for h in header]
            if column.lower() in lowered:
                index = lowered.index(column.lower())
            elif column.isdigit():
                index = int(column)
            else:
                sys.exit(f"column '{column}' not found in header: {header}")
        else:
            index = next(
                (i for i, h in enumerate(header) if "purl" in h.lower()),
                0,
            )
    dropped = []
    for row in body:
        cell = row[index].strip() if index < len(row) else ""
        if cell.lower().startswith("pkg:"):
            raws.append(cell)
        elif any(c.strip() for c in row):
            dropped.append(cell or ",".join(row)[:80])
    return raws, dropped


def write_csv(path, columns, rows):
    # utf-8-sig: Windows' default cp1252 can't encode the unicode that shows up
    # in deprecation notices, and the BOM keeps Excel from mangling the import.
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        writer.writerows(rows)


def write_xlsx(path, plan_rows, alert_rows, summary_rows, run_info):
    try:
        import xlsxwriter
    except ImportError:
        print("xlsxwriter not installed; skipping xlsx output", file=sys.stderr)
        return False
    # strings_to_formulas off: deprecation notices and alert details are
    # attacker-controlled text (a package author writes them); a cell starting
    # with "=" must never open as a live Excel formula in a security report.
    book = xlsxwriter.Workbook(path, {"constant_memory": False, "strings_to_formulas": False})
    header = book.add_format({"bold": True, "bg_color": "#EDE9FE", "border": 1, "text_wrap": True, "valign": "top"})
    wrap = book.add_format({"text_wrap": True, "valign": "top"})

    def sheet(name, columns, rows, widths):
        work = book.add_worksheet(name)
        work.write_row(0, 0, columns, header)
        for index, row in enumerate(rows, start=1):
            work.write_row(index, 0, row, wrap)
        work.freeze_panes(1, 0)
        if rows:
            work.autofilter(0, 0, len(rows), len(columns) - 1)
        for col, width in enumerate(widths):
            work.set_column(col, col, width)
        return work

    sheet("upgrade_plan", PLAN_COLUMNS, plan_rows, [
        60, 14, 14, 16, 70, 22, 60, 10, 32, 42,
        42, 14, 9, 9, 9, 11, 11, 30, 24, 12,
        9, 11, 44, 10, 10, 10, 10, 10, 10, 11,
        11, 9, 16, 10, 9, 22, 60, 30, 16, 34,
        9, 60,
    ])
    sheet("alerts", ALERT_COLUMNS, alert_rows,
          [60, 10, 34, 16, 26, 10, 18, 10, 10, 18, 50, 44, 60])
    sheet("alert_summary", SUMMARY_COLUMNS, summary_rows, [28, 20, 12, 10, 12, 12])
    info = book.add_worksheet("run_info")
    info.write_row(0, 0, ["setting", "value"], header)
    for index, (key, value) in enumerate(run_info, start=1):
        info.write_row(index, 0, [key, str(value)])
    info.set_column(0, 0, 30)
    info.set_column(1, 1, 90)
    book.close()
    return True


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("input", help="CSV or newline-delimited file of purls")
    parser.add_argument("--out", required=True, help="output basename (no extension)")
    parser.add_argument("--org", default=os.environ.get("SOCKET_ORG_SLUG", ""),
                        help="Socket org slug for the org-scoped purl and Fixes API calls "
                             "(required; also settable via SOCKET_ORG_SLUG)")
    parser.add_argument("--purl-column", help="input CSV column holding the purl (name or index)")
    parser.add_argument("--max-candidates", type=int, default=20,
                        help="max versions to probe per package when hunting a safe version")
    parser.add_argument("--probe-chunk", type=int, default=4,
                        help="versions probed per package per round")
    parser.add_argument("--batch-size", type=int, default=250, help="purls per Socket API request")
    parser.add_argument("--stale-years", type=float, default=3.0,
                        help="flag a package whose newest release is older than this many years, "
                             "and say so on the recommendation (default: 3)")
    parser.add_argument("--safe-mode", choices=["policy", "severity", "strict"], default="policy",
                        help="what makes a version unsafe: 'policy' = alerts your org security "
                             "policy acts on (--safe-actions), 'severity' = high/critical or "
                             "vulnerability/malware/deprecated/unmaintained alerts regardless of "
                             "policy, 'strict' = any alert at all (default: policy)")
    parser.add_argument("--safe-actions", default="error,warn",
                        help="policy mode: alert actions that disqualify a version (default: error,warn)")
    parser.add_argument("--include-prerelease", action="store_true",
                        help="allow prereleases as newest/safe versions")
    parser.add_argument("--no-fixes-api", action="store_true",
                        help="skip the Socket Fixes API cross-reference stage (npm/pypi/maven "
                             "packages with known CVEs)")
    parser.add_argument("--minimum-release-age", default="0d",
                        help="Fixes API: only suggest a fix version at least this old, e.g. 2d, "
                             "1w (default: 0d) -- reduces exposure to just-published malicious "
                             "versions")
    parser.add_argument("--no-major-fixes", action="store_true",
                        help="Fixes API: never suggest a fix that requires a major version bump")
    parser.add_argument("--threads", type=int, default=8, help="parallel registry lookups")
    parser.add_argument("--api-threads", type=int, default=4,
                        help="parallel Socket API requests per round")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE)
    parser.add_argument("--cache-ttl", type=int, default=CACHE_TTL)
    parser.add_argument("--no-cache", action="store_true", help="bypass the registry cache")
    parser.add_argument("--no-xlsx", action="store_true")
    parser.add_argument("--alpine-branches", default="latest-stable,edge")
    parser.add_argument("--alpine-repos", default="main,community")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("-v", "--verbose", action="store_true")
    opts = parser.parse_args()

    if not opts.org:
        sys.exit("set --org (or SOCKET_ORG_SLUG) to your Socket org slug")

    opts.actionable_actions = {a.strip() for a in opts.safe_actions.split(",") if a.strip()}
    opts.alpine_branches = [b.strip() for b in opts.alpine_branches.split(",") if b.strip()]
    opts.alpine_repos = [r.strip() for r in opts.alpine_repos.split(",") if r.strip()]
    if opts.safe_mode == "strict":
        opts.alert_label = "Socket alerts"
    elif opts.safe_mode == "severity":
        opts.alert_label = "high/critical, vulnerability, malware, deprecated or unmaintained Socket alerts"
    else:
        opts.alert_label = "/".join(sorted(opts.actionable_actions)) + " Socket alerts"
    opts.safe_label = "no " + opts.alert_label
    opts.actionable = make_actionable(opts)

    token = os.environ.get("SOCKET_API_KEY") or os.environ.get("SOCKET_SECURITY_API_TOKEN")
    if not token:
        sys.exit("set SOCKET_API_KEY (or SOCKET_SECURITY_API_TOKEN)")

    raws, dropped = load_inputs(opts.input, opts.purl_column)
    if not raws:
        sys.exit(f"no purls found in {opts.input}")
    rows, skipped = [], []
    seen = set()
    for raw in raws:
        if raw in seen:
            continue
        seen.add(raw)
        purl = parse_purl(raw)
        if purl is None:
            skipped.append(raw)
            continue
        rows.append(Row(raw, purl))
    tail = f", {len(skipped)} unparsable" if skipped else ""
    if dropped:
        tail += f", {len(dropped)} row(s) with no purl skipped"
    print(f"{opts.input}: {len(raws)} purls -> {len(rows)} unique parsed{tail}")
    for value in (skipped + dropped)[:10]:
        print(f"  skipped: {value}", file=sys.stderr)

    http = Http(opts.cache_dir, ttl=opts.cache_ttl, use_cache=not opts.no_cache, verbose=opts.verbose)
    socket = Socket(token, opts.org, batch_size=opts.batch_size, timeout=opts.timeout,
                    threads=opts.api_threads, verbose=opts.verbose)

    print(f"resolving versions for {len(rows)} packages ...")
    with ThreadPoolExecutor(max_workers=max(1, opts.threads)) as pool:
        infos = list(pool.map(lambda r: lookup_registry(http, r.purl, opts), rows))
    for row, info in zip(rows, infos):
        row.registry = info
        row.purl.version = reconcile_version(row.purl.type, row.purl.version, info.get("versions"))
        row.newest = pick_newest(row.purl.type, info, opts, row.purl.version)
        row.candidates = build_candidates(row, opts)

    print("querying Socket for input versions ...")
    input_purls = [r.purl.socket_purl(r.purl.version) for r in rows]
    socket.query(input_purls)

    fixes_by_key = {}
    if socket.fatal:
        print("skipping Fixes API cross-reference and safe-version probing "
              f"({socket.fatal})", file=sys.stderr)
    elif not opts.no_fixes_api:
        ghsa_hit_raws = set()
        for row, input_purl in zip(rows, input_purls):
            alerts = (socket.cache.get(input_purl) or {}).get("alerts") or []
            if any((a.get("props") or {}).get("ghsaId") for a in alerts):
                ghsa_hit_raws.add(row.raw)
        eligible = [r for r in rows if r.raw in ghsa_hit_raws and r.purl.type in FIXES_API_ECOSYSTEMS]
        skipped_eco = {r.purl.type for r in rows if r.raw in ghsa_hit_raws} - FIXES_API_ECOSYSTEMS
        if eligible:
            print(f"cross-referencing Socket Fixes API for {len(eligible)} package(s) with known CVEs ...")
            fixes_by_key = cross_reference_fixes(eligible, opts.org, token, opts.minimum_release_age,
                                                  not opts.no_major_fixes)
        else:
            print("cross-referencing Socket Fixes API: no CVE-bearing npm/pypi/maven packages in this batch")
        if skipped_eco:
            print(f"  fixes API: {sorted(skipped_eco)} have known CVEs but no manifest synthesizer yet "
                  "(safe_version still covers them)", file=sys.stderr)

    if not socket.fatal:
        print(f"hunting safe versions ({opts.safe_label}) ...")
        probe_safe_versions(rows, socket, opts)

    plans, alert_rows = [], []
    counts = {}
    not_found = 0
    with ThreadPoolExecutor(max_workers=max(1, opts.threads)) as pool:
        results = list(pool.map(lambda r: analyze(r, http, socket, opts, fixes_by_key), rows))
    for row, (plan, alerts, found) in zip(rows, results):
        plans.append(plan)
        if not found:
            not_found += 1
        for alert in alerts:
            atype = alert.get("type")
            if atype == "notFound":
                continue
            action = alert.get("action") or ""
            ghsa_id = (alert.get("props") or {}).get("ghsaId", "")
            fix_hint = (alert.get("fix") or {}).get("description", "") if alert.get("fix") else ""
            alert_rows.append([
                row.raw,
                row.purl.type,
                row.registry.get("display_name") or row.purl.full_name,
                row.purl.version,
                atype,
                alert.get("severity") or "",
                alert.get("category") or "",
                action,
                "TRUE" if opts.actionable(alert) else "FALSE",
                ghsa_id,
                fix_hint,
                alert_detail(alert),
                json.dumps(alert.get("props") or {})[:500],
            ])
            key = (atype, alert.get("category") or "", alert.get("severity") or "", action)
            entry = counts.setdefault(key, {"packages": set(), "count": 0})
            entry["packages"].add(row.raw)
            entry["count"] += 1

    summary_rows = sorted(
        ([k[0], k[1], k[2], k[3], len(v["packages"]), v["count"]] for k, v in counts.items()),
        key=lambda r: (-ACTION_RANK.get(r[3], 0), -SEVERITY_RANK.get(r[2], 0), -r[5], r[0]),
    )
    # deprecated/dead packages first, then Fixes-API-confirmed CVE fixes, then
    # other risk-driven upgrades, then routine ones
    def plan_rank(plan):
        rec_type = plan["recommendation_type"]
        if rec_type == "replace_package":
            return 0
        if rec_type.endswith("_deprecated"):
            return 1
        if rec_type.endswith("_unmaintained"):
            return 2
        return {
            "upgrade_fixes_api": 3, "upgrade_safe": 4, "upgrade_newest": 5, "upgrade_newest_safe": 6,
            "review_release_stream": 7, "no_upgrade_available": 8, "stay_current": 9, "unknown": 10,
        }.get(rec_type, 11)

    plans.sort(key=lambda p: (plan_rank(p), -int(p["input_actionable_alert_count"] or 0),
                              p["ecosystem"], p["package_name"].lower(),
                              version_key(p["ecosystem"], p["input_version"])))
    plan_rows = [[plan[col] for col in PLAN_COLUMNS] for plan in plans]

    plan_csv, alerts_csv, summary_csv = f"{opts.out}.csv", f"{opts.out}_alerts.csv", f"{opts.out}_alert_summary.csv"
    write_csv(plan_csv, PLAN_COLUMNS, plan_rows)
    write_csv(alerts_csv, ALERT_COLUMNS, alert_rows)
    write_csv(summary_csv, SUMMARY_COLUMNS, summary_rows)

    with_fixes_api = sum(1 for p in plans if p["fixes_api_version"])
    run_info = [
        ("org", opts.org),
        ("input", os.path.abspath(opts.input)),
        ("generated (UTC)", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())),
        ("purls in", len(raws)),
        ("purls analyzed", len(rows)),
        ("unparsable purls", len(skipped)),
        ("input rows with no purl", len(dropped)),
        ("safe version mode", opts.safe_mode),
        ("stale package threshold (years)", opts.stale_years),
        ("safe version definition", opts.safe_label),
        ("prereleases considered", opts.include_prerelease),
        ("max candidate versions per package", opts.max_candidates),
        ("Fixes API cross-reference", "disabled" if opts.no_fixes_api else "enabled"),
        ("Fixes API minimum release age", opts.minimum_release_age),
        ("Fixes API ecosystems supported", ", ".join(sorted(FIXES_API_ECOSYSTEMS))),
        ("packages with a Fixes API upgrade path", with_fixes_api),
        ("Socket API requests", socket.requests),
        ("Socket purls queried", len(socket.cache)),
        ("Socket API error", socket.fatal or "none"),
        ("packages with no Socket analysis", not_found),
        ("alert rows", len(alert_rows)),
        ("distinct alert types", len(summary_rows)),
    ]
    xlsx_path = f"{opts.out}.xlsx"
    wrote_xlsx = False if opts.no_xlsx else write_xlsx(xlsx_path, plan_rows, alert_rows, summary_rows, run_info)

    dead = sum(1 for p in plans if p["package_deprecated"] == "TRUE")
    input_deprecated = sum(1 for p in plans if p["input_version_deprecated"] == "TRUE")
    unmaintained = sum(1 for p in plans if p["is_unmaintained"] == "TRUE")
    replacements = sum(1 for p in plans if p["replacement_package"])
    with_safe = sum(1 for p in plans if p["safe_version"])
    print()
    print(f"analyzed {len(plan_rows)} purls | {len(alert_rows)} alerts | "
          f"{with_fixes_api} with a Socket Fixes API upgrade path | "
          f"{with_safe} with a safe version | {input_deprecated} deprecated input versions | "
          f"{dead} deprecated packages | {unmaintained} unmaintained | "
          f"{replacements} with a replacement package | {not_found} not analyzed by Socket")
    print(f"Socket API requests: {socket.requests} ({len(socket.cache)} purls)")
    for path in [plan_csv, alerts_csv, summary_csv] + ([xlsx_path] if wrote_xlsx else []):
        print(f"  {path}")


if __name__ == "__main__":
    main()
