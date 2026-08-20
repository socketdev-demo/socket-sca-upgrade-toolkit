# Socket SCA automation toolkit

Scanning isn't the hard part. You can get a dependency inventory out of Socket
three ways -- the CLI, the API, or the GitHub App -- in an afternoon. The
question that actually determines whether a security team gets value out of
it: once you have those results, what do you *do* with them? Someone still has
to turn a pile of alerts into "upgrade this, ignore that, this one's dead,
replace it."

This repo is two runnable examples of doing that turn programmatically instead
of by hand.

## purl-upgrade/

Input: a list of packages (a CSV export, a manual sample, whatever you've got).
Output: for every package, the newest version, the newest version free of
actionable Socket alerts, Socket's own risk scores, package age, registry and
source links, and -- for anything carrying a known CVE -- the exact fix
version from Socket's Fixes API (the same engine behind `socket fix`), not
just "some later version happened not to trigger an alert."

```
cd purl-upgrade
export SOCKET_API_KEY=...
python3 socket_purl_upgrade.py your_packages.csv --org your-org-slug --out report
```

See `purl-upgrade/README.md` for the full column reference.

## reachability/

Input: a set of manifest files. Output: which of your vulnerability alerts are
actually reachable (worth a PR) versus unreachable (safe to deprioritize),
paired with the exact fix version for the ones that matter. This is the noise
problem: most dependency vulnerability backlogs are dominated by alerts on
code paths nothing calls, and reachability analysis is what tells you which
alerts those are without a human reading the code.

```
cd reachability
export SOCKET_API_KEY=...
python3 reachability_demo.py --org your-org-slug
```

See `reachability/README.md` for how to read the report and the
dashboard-visible (full-scans + CLI) equivalent once this becomes a scheduled
integration rather than an ad hoc check.

## How these fit together

Both scripts are variations on the same three-step shape:

1. **Get manifests or a purl list in front of Socket's API.** Either you
   already have a scan (CLI, API, or GitHub App), or you don't and these
   scripts show the lightweight path that doesn't require one -- upload
   manifests or a purl list directly, no dashboard entry required.
2. **Ask Socket for the two things a security team actually needs: what's the
   right version, and what's actually worth acting on.** That's the Fixes API
   and reachability analysis, respectively. Both are queryable per package or
   per scan, and both are designed to run unattended.
3. **Turn the answer into a CSV, a PR, or a CI gate** -- whatever your
   workflow needs downstream. Neither script assumes a human is reading the
   raw API response.

For a recurring sweep across a large inventory (a scheduled campaign rather
than a one-off check), nothing about the shape changes -- point `--org` and
your input at the right place and run it in CI on whatever cadence the
campaign needs.

## What's documented API versus what's internal

`purl-upgrade` uses the org-scoped purl endpoint and the Fixes API, both
public and documented at docs.socket.dev. `reachability` leads with
`upload-manifest-files` / `compute-artifacts`, which are not in the public API
reference as of this writing -- real, stable in practice, and how Socket's own
pipeline works internally, but worth confirming current behavior with your
Socket contact before treating them as a stable contract. Each script's own
README says exactly which calls fall in which category, and `reachability/README.md`
has the documented full-scans + CLI equivalent validated against the same
sample manifests.

## Requirements

Python 3.9+, stdlib only (`xlsxwriter` optional, for the `.xlsx` output in
`purl-upgrade`). `SOCKET_API_KEY` (or `SOCKET_SECURITY_API_TOKEN`) with
`packages:list`, `fixes:list`, and `full-scans:create` scopes covers
everything both scripts do.
