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
USER_AGENT = "socket-purl-upgrade/2.0 (+https://socket.dev)"
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
# PEP440 / Maven style markers that open a prerelease segment: 1.0b1, 5.0.0-M2, 2.0a3
PRERELEASE_HEAD_RE = re.compile(
    r"^(?:alpha|beta|rc|prerelease|preview|pre|dev|snapshot|nightly|canary|next"
    r"|milestone|cr|eap|unstable|insiders|[abcm])\d*(?:$|[._\-+])"
)

# Ecosystems the Fixes API cross-reference knows how to synthesize a manifest for.
FIXES_API_ECOSYSTEMS = {"npm", "pypi", "maven"}
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


def registry_link(purl):
    """Human-facing registry page for a purl. Pure and deterministic -- no I/O."""
    eco, name, version = purl.type, purl.full_name, purl.version
    if eco == "npm":
        return f"https://www.npmjs.com/package/{name}" + (f"/v/{version}" if version else "")
    if eco == "pypi":
        return f"https://pypi.org/project/{name}/" + (f"{version}/" if version else "")
    if eco == "maven" and purl.namespace:
        base = f"https://central.sonatype.com/artifact/{purl.namespace}/{purl.name}"
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
    """Tolerant ISO-8601 parse for the handful of date formats the registries use."""
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


# --------------------------------------------------------------------------- #
# version ordering
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")
_RELEASE_RE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


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
    text = str(version or "").strip()
    if re.match(r"^[vV]\d", text):
        text = text[1:]
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
    tail = tail.lstrip("-._")
    rank = 1
    if tail:
        words = {w for w in re.findall(r"[A-Za-z]+", tail.lower())}
        if eco in SEMVER_ECOSYSTEMS:
            rank = 0  # SemVer/NuGet: any dash-suffix precedes the release, no exceptions
        elif words & PRERELEASE_WORDS or PRERELEASE_HEAD_RE.match(tail.lower()):
            rank = 0
        elif words & POST_WORDS:
            rank = 2
    return (release, rank, _tokens(tail), extra)


def is_prerelease(eco, version):
    return version_key(eco, version)[1] == 0


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


def maven_registry(http, purl):
    info = empty_registry()
    if not purl.namespace:
        info["error"] = "maven purl missing groupId"
        return info
    group_path = purl.namespace.replace(".", "/").replace("//", "/")
    url = f"https://repo1.maven.org/maven2/{group_path}/{purl.name}/maven-metadata.xml"
    info["source"] = url

    def parse(raw):
        root = ET.fromstring(raw)
        versions = [e.text for e in root.iter("version") if e.text]
        release = root.findtext("./versioning/release") or None
        updated = root.findtext("./versioning/lastUpdated") or ""
        return {"versions": versions, "release": release, "lastUpdated": updated}

    doc = http.cached_json(url, parser=parse)
    if not doc:
        info["error"] = "maven central lookup failed"
        return info
    info["versions"] = doc["versions"]
    info["latest"] = doc.get("release")
    info["last_publish"] = doc.get("lastUpdated") or ""
    info["display_name"] = f"{purl.namespace}:{purl.name}"
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


def pick_newest(eco, info, opts):
    versions = info.get("versions") or []
    unusable = info.get("unusable") or {}
    usable = [v for v in versions if v not in unusable]
    if not opts.include_prerelease:
        stable = [v for v in usable if not is_prerelease(eco, v)]
        if stable:
            usable = stable
    latest = info.get("latest")
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
    pool = set()
    for version in info.get("versions") or []:
        if version in unusable:
            continue
        if not opts.include_prerelease and is_prerelease(eco, version) and version != input_version:
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

    registry_url = registry_link(purl)
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

    input_is_newest = bool(
        newest_version and purl.version
        and version_key(eco, purl.version) >= version_key(eco, newest_version)
    )

    if info.get("error"):
        row.notes.append(info["error"])
    # apk indexes only current branches and the github client only pages the
    # newest 300 tags, so absence there proves nothing; every other registry
    # client returns the complete version list.
    if purl.version and info.get("versions") and purl.version not in info["versions"] \
            and eco not in ("apk", "github"):
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
    with open(path, "w", newline="") as fh:
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
        row.newest = pick_newest(row.purl.type, info, opts)
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
            "no_upgrade_available": 7, "stay_current": 8, "unknown": 9,
        }.get(rec_type, 10)

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
