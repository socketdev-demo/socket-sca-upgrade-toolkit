#!/usr/bin/env python3
"""Reachability + Fixes API walkthrough: manifests in, a noise-reduction report out.

This is the "what do we do with scan results" half of the toolkit. It takes the
manifest files in manifests/ (a small app with real, known-CVE dependencies, both
direct and transitive) and shows the automatable API path from "here are our
manifests" to "here is what's actually worth fixing":

  1. Upload the manifests (upload-manifest-files) -> a content-addressed tarHash.
     No dashboard entry, no repo, nothing persisted -- a pure compute call.
  2. Ask for Socket's Tier 2 (precomputed) reachability on top of that tarHash
     (compute-artifacts?includePrecomputedReachabilityResults=true). This is the
     noise-reduction lever: most orgs' vulnerability backlogs are dominated by
     alerts on code paths nothing ever calls. Tier 2 traces call graphs between
     PACKAGES -- so it earns its keep on transitive dependencies, where it can
     tell you the vulnerable function in a sub-dependency is never called by the
     package that pulled it in. For your own DIRECT dependencies, Tier 2 has no
     visibility into whether *your* code calls the vulnerable function -- it
     correctly reports "direct_dependency" (needs a look) rather than guessing.
     Closing that gap is what Tier 1 (full application reachability, `--reach`,
     needs your source checked out) is for. See README.md for both.
  3. Cross-reference the same tarHash against the Fixes API (GET .../fixes) to
     attach an exact, dependency-graph-aware fix version to every finding that
     needs one -- the two things a security team actually needs: what's real,
     and what version makes it not real anymore.

Everything here runs against two Socket endpoints that are not in the public API
reference (upload-manifest-files, compute-artifacts) -- verified live and stable
in practice, but confirm current behavior with your Socket contact before building
production automation on them. The Fixes API (GET /orgs/{org}/fixes) and the
full-scans API are public and documented; see README.md in this directory for the
equivalent, dashboard-visible flow using full-scans + the socket CLI, which is the
path to use once you're ready to make this a persistent, scheduled integration
rather than an ad hoc check.

Usage:
    export SOCKET_API_KEY=...
    python3 reachability_demo.py --org my-org-slug
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SOCKET_API_BASE = "https://api.socket.dev/v0"
USER_AGENT = "socket-reachability-demo/1.0 (+https://socket.dev)"
DEFAULT_MANIFEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifests")

# Every file in manifests/ is uploaded as-is; this is just which ones we expect
# to find there so a partial checkout gives a clear error instead of a confusing one.
EXPECTED_MANIFESTS = ["package.json", "package-lock.json", "requirements.txt", "pom.xml"]

# Tier 2's own verdict vocabulary (precomputedReachabilityResult.type), grouped
# for the summary. "direct_dependency" is Socket being honest about a real
# limit, not a missing feature -- see the module docstring.
UNREACHABLE_VERDICTS = {"unreachable"}
CONFIRMED_VERDICTS = {"reachable", "maybe_reachable"}
# Everything else -- direct_dependency, unknown, undeterminable_reachability,
# no_verdict, and any verdict string this script hasn't met yet -- lands in the
# "needs a closer look" bucket, computed by subtraction below so a new verdict
# in Socket's vocabulary can never silently vanish from the summary math.

# compute-artifacts returns one record per stored artifact, and a single pypi
# requirements line resolves against every Python environment Socket models --
# one pyyaml pin comes back as 13 records (verified live), each repeating the
# same vulnerabilities. Findings are merged on (package, GHSA); when duplicate
# records ever disagree on the verdict, the more-reachable claim wins, because
# "some environment reaches it" is the security-relevant answer.
VERDICT_PRIORITY = {
    "reachable": 5, "maybe_reachable": 4, "direct_dependency": 3,
    "undeterminable_reachability": 3, "unknown": 2, "no_verdict": 1, "unreachable": 0,
}
# Verdict strings not in the map rank with direct_dependency: an answer this
# script doesn't understand must never lose a merge to "unreachable".
UNKNOWN_VERDICT_PRIORITY = 3


def basic_auth_header(token):
    return "Basic " + base64.b64encode((token + ":").encode()).decode()


def _multipart_encode(fields):
    """fields: [(name, content)]. Plain form fields -- NO filename= attribute.

    Verified live: sending a manifest as a file part (curl's -F name=@file, or a
    Content-Disposition with filename=) makes the server store empty bytes for
    that part. The field NAME must be the manifest's path (e.g. "package.json")
    and the VALUE must be the raw content, as a plain form field.
    """
    boundary = "socketreach" + hashlib.sha1(os.urandom(16)).hexdigest()
    body = bytearray()
    for name, content in fields:
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += content if isinstance(content, bytes) else content.encode()
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _request(method, url, token, body=None, content_type=None, timeout=120):
    headers = {"Authorization": basic_auth_header(token), "User-Agent": USER_AGENT}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def load_manifests(manifest_dir):
    found = []
    for name in sorted(os.listdir(manifest_dir)):
        if name.startswith("."):  # .DS_Store and friends
            continue
        path = os.path.join(manifest_dir, name)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                found.append((name, fh.read()))
    missing = [name for name in EXPECTED_MANIFESTS if name not in {n for n, _ in found}]
    return found, missing


def upload_manifest_files(org, token, manifests):
    """POST /v0/orgs/{org}/upload-manifest-files -> (tarHash, unmatchedFiles)."""
    body, content_type = _multipart_encode(manifests)
    url = f"{SOCKET_API_BASE}/orgs/{urllib.parse.quote(org)}/upload-manifest-files"
    raw = _request("POST", url, token, body=body, content_type=content_type)
    doc = json.loads(raw)
    return doc.get("tarHash"), doc.get("unmatchedFiles") or []


def compute_artifacts(org, token, tar_hash):
    """POST /v0/orgs/{org}/compute-artifacts?tarHash=...&includePrecomputedReachabilityResults=true
    -> list of resolved-package dicts (NDJSON envelope {"type":"artifact","value":{...}}
    unwrapped to just the value)."""
    params = {"tarHash": tar_hash, "includePrecomputedReachabilityResults": "true"}
    url = f"{SOCKET_API_BASE}/orgs/{urllib.parse.quote(org)}/compute-artifacts?" + urllib.parse.urlencode(params)
    raw = _request("POST", url, token)
    values = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line == b'"':
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("type") == "artifact" and isinstance(record.get("value"), dict):
            values.append(record["value"])
    return values


def fetch_fixes(org, token, tar_hash, min_release_age="0d", allow_major_updates=True):
    """GET /v0/orgs/{org}/fixes?tar_hash=...&vulnerability_ids=* -> fixDetails dict."""
    params = {
        "tar_hash": tar_hash,
        "vulnerability_ids": "*",
        "include_details": "true",
        "minimum_release_age": min_release_age,
        "allow_major_updates": "true" if allow_major_updates else "false",
    }
    url = f"{SOCKET_API_BASE}/orgs/{urllib.parse.quote(org)}/fixes?" + urllib.parse.urlencode(params)
    raw = _request("GET", url, token)
    return json.loads(raw).get("fixDetails") or {}


def reachability_verdict(vuln):
    """Tier 2 verdict for one vulnerabilities[] entry. "no_verdict" (distinct
    from the real "unknown" verdict Tier 2 can itself return) means this
    specific CVE entry carried no reachabilityData at all -- Socket had
    nothing to say about it, rather than saying "unknown" affirmatively."""
    result = (vuln.get("reachabilityData") or {}).get("precomputedReachabilityResult") or {}
    return result.get("type") or "no_verdict"


def artifact_full_name(value):
    """Namespace-qualified package name for a compute-artifacts record.
    Scoped npm packages and maven artifacts come back with the scope/groupId
    in a separate `namespace` field (verified live: @babel/traverse arrives as
    namespace='@babel', name='traverse')."""
    name = value.get("name") or "?"
    namespace = value.get("namespace") or ""
    return f"{namespace}/{name}" if namespace else name


def purl_match_key(purl_str):
    """(ecosystem, namespace-qualified name) key. compute-artifacts reports
    ecosystem/namespace/name/version as separate fields, not a purl string,
    so this is the join key used to line up a Fixes API result (which does
    return full purls) against an artifact. The namespace stays in the key:
    real manifest sets carry the same bare name under different namespaces
    (maven artifactIds especially, e.g. javax.servlet:servlet-api vs
    org.mortbay.jetty:servlet-api), and dropping it would let one package's
    fix attach to another package's finding."""
    body = purl_str[4:] if purl_str.startswith("pkg:") else purl_str
    eco, _, rest = body.partition("/")
    at = rest.rfind("@")
    if at > 0:  # a leading @ is an npm scope, not a version separator
        rest = rest[:at]
    name = "/".join(urllib.parse.unquote(s) for s in rest.split("/") if s)
    return (eco, name)


def build_fix_index(fix_details):
    """(ecosystem, full name, ghsa) -> {fixed_version, update_type, kev, epss}.

    Keyed per-GHSA, not per-package: a package can carry several CVEs that
    don't all resolve at the same target version, and "this package has *a*
    fix somewhere" is not the same claim as "this specific finding is fixed."
    """
    index = {}
    for ghsa, variant in fix_details.items():
        value = variant.get("value") or {}
        fixes = ((value.get("fixDetails") or {}).get("fixes")) or []
        advisory = value.get("advisoryDetails") or {}
        kev = bool(advisory.get("kev"))
        # epss is a plain float on the live response (verified); tolerate the
        # {"score": ...} object shape too rather than silently dropping it.
        epss_obj = advisory.get("epss")
        if isinstance(epss_obj, (int, float)) and not isinstance(epss_obj, bool):
            epss = epss_obj
        elif isinstance(epss_obj, dict):
            epss = epss_obj.get("score")
        else:
            epss = None
        for fix in fixes:
            purl_str = fix.get("purl") or ""
            fixed_version = fix.get("fixedVersion")
            if not purl_str or not fixed_version:
                continue
            eco, name = purl_match_key(purl_str)
            index[(eco, name, ghsa)] = {
                "fixed_version": fixed_version,
                "update_type": fix.get("updateType") or "",
                "kev": kev,
                "epss": epss,
            }
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--org", default=os.environ.get("SOCKET_ORG_SLUG", ""),
                        help="Socket org slug (required; also settable via SOCKET_ORG_SLUG)")
    parser.add_argument("--manifests-dir", default=DEFAULT_MANIFEST_DIR,
                        help=f"directory of manifest files to upload (default: {DEFAULT_MANIFEST_DIR})")
    parser.add_argument("--minimum-release-age", default="0d",
                        help="Fixes API: only suggest a fix version at least this old, e.g. 2d, 1w")
    parser.add_argument("--no-major-fixes", action="store_true",
                        help="Fixes API: never suggest a fix requiring a major version bump")
    parser.add_argument("--out", default="reachability_report.csv",
                        help="CSV report path (default: reachability_report.csv)")
    parser.add_argument("-v", "--verbose", action="store_true")
    opts = parser.parse_args()

    if not opts.org:
        sys.exit("set --org (or SOCKET_ORG_SLUG) to your Socket org slug")
    token = os.environ.get("SOCKET_API_KEY") or os.environ.get("SOCKET_SECURITY_API_TOKEN")
    if not token:
        sys.exit("set SOCKET_API_KEY (or SOCKET_SECURITY_API_TOKEN)")

    manifests, missing = load_manifests(opts.manifests_dir)
    if not manifests:
        sys.exit(f"no files found in {opts.manifests_dir}")
    if missing:
        print(f"note: {opts.manifests_dir} is missing {missing} -- continuing with "
              f"{[n for n, _ in manifests]}", file=sys.stderr)

    print(f"uploading {len(manifests)} manifest file(s) from {opts.manifests_dir} ...")
    try:
        tar_hash, unmatched = upload_manifest_files(opts.org, token, manifests)
    except urllib.error.HTTPError as err:
        sys.exit(f"upload-manifest-files failed: HTTP {err.code} -- {err.read()[:300]}")
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        sys.exit(f"upload-manifest-files failed: {err}")
    if not tar_hash:
        sys.exit("upload-manifest-files did not return a tarHash")
    if unmatched:
        print(f"  {len(unmatched)} file(s) did not resolve to a supported ecosystem: {unmatched}",
              file=sys.stderr)
    print(f"  tarHash: {tar_hash}")

    print("computing artifacts with precomputed (Tier 2) reachability ...")
    try:
        artifact_values = compute_artifacts(opts.org, token, tar_hash)
    except urllib.error.HTTPError as err:
        sys.exit(f"compute-artifacts failed: HTTP {err.code} -- {err.read()[:300]}")
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        sys.exit(f"compute-artifacts failed: {err}")
    print(f"  resolved {len(artifact_values)} artifact(s)")

    print(f"cross-referencing the Socket Fixes API (minimum_release_age={opts.minimum_release_age}) ...")
    try:
        fix_details = fetch_fixes(opts.org, token, tar_hash, opts.minimum_release_age,
                                   not opts.no_major_fixes)
    except urllib.error.HTTPError as err:
        print(f"  fixes API failed: HTTP {err.code} -- {err.read()[:300]}; "
              "continuing without fix versions", file=sys.stderr)
        fix_details = {}
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        print(f"  fixes API failed: {err}; continuing without fix versions", file=sys.stderr)
        fix_details = {}
    fix_index = build_fix_index(fix_details)

    findings_by_key = {}
    packages = set()
    for value in artifact_values:
        eco = value.get("type") or "?"
        full_name = artifact_full_name(value)
        version = value.get("version") or ""
        direct = bool(value.get("direct"))
        if version:  # skip Socket's synthetic version-less resolver artifact
            packages.add((eco, full_name, version))
        for vuln in value.get("vulnerabilities") or []:
            verdict = reachability_verdict(vuln)
            ghsa = vuln.get("ghsaId", "")
            key = (eco, full_name, version, ghsa)
            prior = findings_by_key.get(key)
            if prior is not None:
                # duplicate per-environment record: keep the worst-case verdict
                if VERDICT_PRIORITY.get(verdict, UNKNOWN_VERDICT_PRIORITY) > \
                        VERDICT_PRIORITY.get(prior["reachability"], UNKNOWN_VERDICT_PRIORITY):
                    prior["reachability"] = verdict
                prior["direct"] = prior["direct"] or direct
                continue
            fix = fix_index.get((eco, full_name, ghsa), {})
            findings_by_key[key] = {
                "package": f"{eco}/{full_name}@{version or '?'}",
                "direct": direct,
                "ghsa": ghsa,
                "severity": vuln.get("severity", ""),
                "reachability": verdict,
                "fixed_version": fix.get("fixed_version", ""),
                "update_type": fix.get("update_type", ""),
                "kev": "TRUE" if fix.get("kev") else ("FALSE" if fix else ""),
                "epss": "" if fix.get("epss") is None else fix["epss"],
            }

    findings = list(findings_by_key.values())
    for f in findings:
        f["direct"] = "TRUE" if f["direct"] else "FALSE"
    verdict_counts = {}
    for f in findings:
        verdict_counts[f["reachability"]] = verdict_counts.get(f["reachability"], 0) + 1

    total = len(findings)
    unreachable = sum(1 for f in findings if f["reachability"] in UNREACHABLE_VERDICTS)
    confirmed = sum(1 for f in findings if f["reachability"] in CONFIRMED_VERDICTS)
    needs_source = total - unreachable - confirmed

    print()
    print(f"{total} vulnerability finding(s) across {len(packages)} resolved package(s):")
    for verdict, count in sorted(verdict_counts.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict:20s} {count}")
    if total:
        print()
        print(f"unreachable, deprioritize now:      {unreachable:3d} ({round(100 * unreachable / total)}%) "
              "-- Tier 2 traced the call graph and the vulnerable function is never reached")
        print(f"reachable, fix now:                 {confirmed:3d} ({round(100 * confirmed / total)}%) "
              "-- confirmed exposure")
        print(f"needs a closer look (direct/unknown): {needs_source:3d} ({round(100 * needs_source / total)}%) "
              "-- mostly your own direct dependencies: Tier 2 can't see whether *your* code "
              "calls the vulnerable function without your source (that's Tier 1, --reach)")
        with_fix = sum(1 for f in findings if f["fixed_version"])
        print(f"\n{with_fix}/{total} finding(s) already have a Socket Fixes API upgrade path")

    with open(opts.out, "w") as fh:
        cols = ["package", "direct", "ghsa", "severity", "reachability", "fixed_version",
                "update_type", "kev", "epss"]
        fh.write(",".join(cols) + "\n")
        for f in findings:
            fh.write(",".join(str(f[c]).replace(",", ";") for c in cols) + "\n")
    print(f"\nwrote {opts.out}")


if __name__ == "__main__":
    main()
