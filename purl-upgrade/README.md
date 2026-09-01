# Purl upgrade planner

You've got a list of packages (a CSV export from a vulnerability scanner, a
manual sample someone emailed over, whatever) and you want to know, for each
one: what's the newest version, is there a version with no actionable Socket
alerts, and if the package itself is dead, what should replace it. This script
answers all three, deterministically, from Socket's data and the upstream
registries -- no manual per-package research.

## Run it

```
export SOCKET_API_KEY=...          # or SOCKET_SECURITY_API_TOKEN
python3 socket_purl_upgrade.py input.csv --org your-org-slug --out report
```

`input.csv` is a CSV (purl column auto-detected) or a plain text file, one purl
per line. Purls are standard package identifiers
([purl spec](https://github.com/package-url/purl-spec)) naming an ecosystem,
package, and version:

```
pkg:npm/lodash@4.17.20
pkg:npm/@scope/some-package@1.2.3
pkg:pypi/django@3.2
pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

Outputs: `report.csv` / `report_alerts.csv` / `report_alert_summary.csv` and a
4-sheet `report.xlsx` (needs the optional `xlsxwriter` package; skipped with a
note if it isn't installed, or skip explicitly with `--no-xlsx`).

First time using the Socket API? The top-level README's Requirements section
covers creating a token, the scopes these scripts need, and finding your org
slug.

## What's in the report

- **newest_version / safe_version** -- newest release, and the newest release
  Socket doesn't flag under your chosen `--safe-mode` (default: alerts your org
  policy would act on). Both stay inside the input version's release stream
  (see below) and skip prereleases unless you pass `--include-prerelease`.
- **fixes_api_version** -- for npm, pypi, and maven packages carrying a known
  CVE, the exact version the Socket Fixes API computes (the same
  dependency-graph-aware engine behind `socket fix`), with the specific GHSAs
  it resolves, CISA KEV status, and update type (patch/minor/major). This is
  more precise than `safe_version` alone: `safe_version` just checks whether
  Socket alerts on a given version in isolation; the Fixes API accounts for
  transitive impact across the dependency graph. When they disagree, the
  `notes` column says so and the recommendation prefers the Fixes API.
- **socket_\*_score** -- Socket's own 0-100 scores (overall, supply chain,
  quality, maintenance, vulnerability, license), already on the purl API
  response.
- **input_version_published_at / input_version_age_days** -- package age.
  Prefers Socket's own `publishedAt`, falls back to the registry's per-version
  publish date when Socket hasn't backfilled it (common for older packages).
  `age_source` says which one fired.
- **registry_link / source_code_link** -- human-facing registry page, and the
  repository URL where the registry exposes one (npm, pypi, cargo, rubygems,
  nuget). Maven doesn't carry a per-version source link in its metadata index,
  so that column is blank for maven rows -- a real gap, not a bug, and one
  Socket is well positioned to close at scale by resolving it once centrally
  instead of leaving every downstream tool to guess.
- **replacement_package** -- when the newest release is itself deprecated,
  the package the registry (or the deprecation notice) names as the successor.
- Every Socket alert on the input version, in `_alerts.csv`, with the GHSA id
  and the `socket fix --id ...` hint Socket attaches to fixable ones.

## Why this needs `--org`

`POST /v0/purl` (no org scope) was deprecated 2026-01-05 and its stated
removal date has already passed. This script uses the org-scoped successor,
`POST /v0/orgs/{org}/purl`, which is not deprecated and additionally supports
repo-label policy scoping.

## The Fixes API cross-reference, mechanically

For every input purl with a GHSA-bearing alert, in an ecosystem this script
knows how to synthesize a manifest for (npm/pypi/maven), it builds a minimal,
exact-pinned manifest (`package.json` / `requirements.txt` / `pom.xml`) for
just those packages, uploads it (`upload-manifest-files` -- callable with your
ordinary API token, though not yet in the public API reference; see the
top-level README), and asks
`GET /orgs/{org}/fixes?tar_hash=...&vulnerability_ids=*` for the fix. Large
batches go 40 packages per call: the dependency-graph resolution behind
`/fixes` is compute-heavy server-side (measured live: ~50s at 40 packages,
~260s at 100, timeout at 200+), and a manifest can pin only one version per
package name, so same-name different-version inputs also split across calls.
Each fix is keyed to the exact input version it applies to. Gate
suggested versions by age with `--minimum-release-age` (e.g. `2d`), or turn
this stage off entirely with `--no-fixes-api` if your token doesn't have the
`fixes:list` / `full-scans:create` scopes. Other ecosystems (golang, cargo,
gem, nuget, github, apk) fall back to `safe_version` alone -- the pattern
extends to any of them; only the manifest-synthesis step is unwritten for
those.

## Stale packages

A version can carry no alerts and still be a poor recommendation, because
nothing has shipped in a decade. Socket's unmaintained alert catches many of
those but not all, so `package_last_release_days` and `stale_package` are
computed independently from the newest release's publish date. Past
`--stale-years` (default 3) the recommendation itself carries the caveat, not
just a column:

```
Upgrade to 1.1 (newest release and no error/warn Socket alerts) - caution: no
release in 17.9 years (last 2008-09-26), so verify the package is still
maintained
```

Rows already described as deprecated or unmaintained don't repeat it. Where no
publish date is available the columns stay blank and no claim is made in
either direction, rather than treating "unknown" as "fresh".

Maven needs a second source for this. `maven-metadata.xml` carries no
per-version dates, and on older artifacts it omits `lastUpdated` entirely and
can even be missing versions (jdom's metadata lists 1.0 but not 1.1). When
that happens the lookup falls back to Maven Central's search index, which has
a timestamp on every row, and merges in any versions the metadata left out.

## Release streams

Some packages publish several streams side by side under one coordinate, each
with its own numbering. Apache Kafka's OSS line runs `4.3.1` while Confluent
ships `8.3.1-ce` and `8.3.1-ccs` built from that same 4.3.x source; Guava
ships `-jre` and `-android` in parallel. Comparing across them is meaningless,
and "highest number wins" would tell a team on OSS Kafka to install a
Confluent build.

Recommendations therefore stay inside the stream the input version came from.
A version's stream is the alphabetic part of its qualifier tail, so `4.3.1` is
mainline, `8.3.1-ccs` is the `ccs` stream, and `1.2.3-1` (a numeric rebuild)
is still mainline. Prereleases are a stage of the mainline, not a separate
stream, and are handled separately.

Two consequences worth knowing:

- When a package's version list mixes streams, the excluded ones are named in
  `notes`, but only when one of them would otherwise have won the
  recommendation.
- When the input's stream isn't published in the public registry at all (a
  vendor or internal Artifactory build), there's no honest upgrade target to
  name, so `recommendation_type` is `review_release_stream` and the row says
  so instead of pointing at a mainline version that isn't a drop-in swap.

## Everything else

Version comparison, prerelease handling, deprecation-notice parsing, and the
replacement-package lookup are unchanged from the original prototype this
builds on. See the module docstring in `socket_purl_upgrade.py` for the full
option list (`--safe-mode`, `--include-prerelease`, `--threads`, caching,
Alpine branch/repo selection, etc.).
