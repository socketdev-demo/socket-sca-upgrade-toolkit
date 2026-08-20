# Reachability + Fixes API walkthrough

You've scanned your dependencies (CLI, API, or the GitHub App). Now what?

This example answers that for the noise problem specifically: most dependency
vulnerability backlogs are dominated by alerts on code paths nothing ever calls.
Reachability analysis tells you which alerts are real exposure and which are
safe to deprioritize, and the Fixes API tells you the exact version that
resolves the real ones. `reachability_demo.py` runs both, end to end, against
the sample manifests in `manifests/` (a small app with real, known-CVE
dependencies, mixing direct and transitive).

## Run it

```
export SOCKET_API_KEY=...          # or SOCKET_SECURITY_API_TOKEN
python3 reachability_demo.py --org your-org-slug
```

That's the whole setup. No repo to create, nothing to check into a dashboard.

## What it does

1. **Upload the manifests.** `POST /orgs/{org}/upload-manifest-files` takes the
   files in `manifests/` and returns a content-addressed `tarHash`. This is a
   pure compute call -- no scan record, no repo entry, nothing persisted.
2. **Compute Tier 2 (precomputed) reachability.**
   `POST /orgs/{org}/compute-artifacts?tarHash=...&includePrecomputedReachabilityResults=true`
   resolves every package in the manifests and, for each vulnerability, reports
   whether the vulnerable function is actually reachable from the packages that
   depend on it.
3. **Cross-reference the Fixes API.** `GET /orgs/{org}/fixes?tar_hash=...` (the
   same engine behind `socket fix`) returns the dependency-graph-aware fix
   version for every vulnerability it can resolve, plus CISA KEV status and
   EPSS score where available.

## Reading the report

The script buckets every finding into three groups:

- **Unreachable.** Tier 2 traced the call graph between packages and the
  vulnerable function is never reached. Safe to deprioritize without a human
  reading any code.
- **Reachable / maybe_reachable.** Confirmed exposure. These are the ones
  worth a PR, and the report already attaches the Fixes API's exact target
  version to each.
- **Direct dependency / no verdict.** This is the honest limit of Tier 2, not
  a gap in the demo: Tier 2 reasons about the call graph *between packages*.
  For something your own application code depends on directly, Socket has no
  visibility into whether *your* code calls the vulnerable function -- that
  requires Tier 1 (full application reachability), which reads your actual
  source in CI. In this sample, every package pinned directly in
  `package.json` / `requirements.txt` / `pom.xml` lands here; the packages
  pulled in *transitively* (`body-parser`, `qs`, `cookie`, `send`,
  `serve-static`, `path-to-regexp`, `log4j-api`) get real reachable /
  unreachable verdicts, because Tier 2 can see the whole chain between them
  and the packages that pull them in.

That split is the actual pitch for running this at scale: Tier 2 needs nothing
but your manifests and already clears the transitive tail, which is usually
most of the alert volume. Tier 1 is what closes the gap on your own call sites,
once you're ready to add one CLI flag in CI.

## Two endpoints here aren't in the public API reference

`upload-manifest-files` and `compute-artifacts` are not documented at
`docs.socket.dev` as of this writing. They're real, stable in practice, and
this is exactly how Socket's own scanning pipeline uses them internally, but
confirm current behavior and quota terms with your Socket contact before
building production automation on them or committing to them contractually.
The Fixes API (`GET /orgs/{org}/fixes`) and everything below are public and
documented.

## The production-recommended path: full-scans + the CLI

Once this is a persistent, scheduled integration instead of an ad hoc check,
run it as a real scan so it shows up on the dashboard and Socket tracks it over
time. Both of these were validated live against this same `manifests/`
directory:

```
# Tier 2 (precomputed) reachability is automatic on a normal scan --
# no extra flag needed.
socket scan create ./manifests --repo my-app --branch main --report --json

# Tier 1 (full application reachability) needs your actual source tree,
# not just manifests -- point it at the repo root, not a manifests-only folder.
socket scan create --reach . --repo my-app --branch main --report --json
```

`--report` makes the command exit non-zero on a policy violation, so it drops
straight into a CI gate. Pull every alert on the resulting scan back out with:

```
socket scan view <scan-id> --json
```

which includes `reachability.head.type` per alert (`precomputed`, `full-scan`,
or absent). Or via the API directly: `GET /orgs/{org}/alerts?filters.alertReachabilityAnalysisType=precomputed`.

## Scaling this

For a large, recurring sweep (a scheduled campaign across a big dependency
inventory rather than a one-off check), the shape doesn't change: manifests in,
this script's three stages, a CSV out. Point `--manifests-dir` at each repo's
checkout in CI, or adapt `load_manifests()` to pull from wherever your manifests
already live (a GitHub Action matrix, an artifact store, whatever your existing
scan pipeline produces). The Fixes API and compute-artifacts calls are already
batched per ecosystem, not per package, so this doesn't turn into one API call
per dependency.
