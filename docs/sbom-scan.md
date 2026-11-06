# sbom-scan reference

The `sbom-scan` action and `bin/sbom-scan`. Inputs, outputs and a calling example are in the
[README](../README.md#sbom-scan).

For each source the scan generates an SBOM with [syft](https://github.com/anchore/syft), matches it
against vulnerability data with [grype](https://github.com/anchore/grype), writes the report, and
fails on fixable findings at or above a severity. It runs as a step of the caller's job, so it can
scan an image the job has just built and loaded, before anything pushes it.

## Severities and the gate

Severities are grype's: Critical (CVSS ≥ 9.0), High (7.0–8.9), Medium, Low, Negligible, Unknown.
For OS packages the distribution's own severity wins over CVSS.

The gate counts every finding grype did not ignore whose severity is at least `fail-on` and, with
`only-fixed`, that has a fix available. Unknown severity never counts. A finding with no fix cannot
be acted on by a rebuild, so by default it is reported (in `unfixed-high` and the step summary) but
does not fail the build. The report and `summary.json` are always produced; the gate is decided from
them, not from grype's exit code.

The job's step summary gets a Markdown report: per source, a table of the Medium-and-above findings
(CVE, package, version, severity, fix, EPSS, KEV, the ignore rule that accepted it), the
High-and-above findings without a fix, then the totals and the gate verdict.

## Output files

Per source, `<slug>` is `sha256-<hex>` when the source carries `@sha256:`, else the source with
every character outside `[A-Za-z0-9._-]` replaced by `-`.

| file | content |
|---|---|
| `sbom/<slug>.cdx.json` | CycloneDX 1.6 JSON SBOM |
| `sbom/<slug>.syft.json` | syft JSON SBOM, the one grype scans |
| `sbom/<slug>` (with the file's extension appended when the slug lacks it) | for an `sbom:` source, the SBOM as given |
| `reports/<slug>.grype.json` | grype's JSON report, including `ignoredMatches` |
| `errors/<slug>.txt` | why the source failed to scan, when it did |
| `grype.yaml` | the ignore ledger the scan used (`ignore: []` when none was given); absent with `public` |
| `summary.json` | the gate, per-source counts and findings, totals |

## summary.json

```
{generated_at, gate: {fail_on, only_fixed, failed},
 sources: [{source, slug, digest|null, error?,
            counts: [{severity, fix_state, kev, count}],
            findings: [{id, package, version, type, severity, fix_state, fix_versions, epss, kev, ignored_by|null}]}],
 totals: {fixable_high, fixable_critical, unfixed_high, unfixed_critical, ignored_high, ignored_critical, kev, ignored_kev, errors}}
```

A source whose fetch, syft or grype failed carries `error`, the message, with empty `counts` and
`findings`; `totals.errors` counts those sources, and the report lists them. The other sources are
still scanned, and the step then fails whatever the gate says, also with `fail: false`.

`counts` covers every severity of the findings not ignored; `findings` holds Medium and above,
ignored ones included. In `totals`, the `_high` counts include Critical and each `_critical` is
their Critical part; `ignored_*` count findings an ignore rule accepted, fixed or not, and every
other total counts findings not ignored. `kev` and `ignored_kev` count every severity. `fix_state`
is grype's: `fixed`, `not-fixed`, `wont-fix` or `unknown`.

`ignored_by` is the `reason` of the rule that accepted the finding, or the literal `accepted` with
`public`.

## Ignore rules

Ignore rules come from the caller's ledger: `ignore-file`, or `.grype.yaml` at the workspace root.
With neither, the scan runs with no ignore rules. Ignored findings stay in the report, attributed to
the rule's `reason`.

A rule is scoped by a vulnerability, by a package, or by both. Every rule needs a non-empty
`reason` and `expires` as `YYYY-MM-DD`, no more than 180 days ahead; an expired or malformed rule
fails the scan.

A vulnerability rule names one `vulnerability`. Any other
[grype ignore field](https://oss.anchore.com/docs/guides/vulnerability/filter-results/) narrows it:

```yaml
ignore:
  - vulnerability: CVE-2024-12345
    package:
      name: libfoo          # an anchored regex
    fix-state: not-fixed
    reason: not reachable — the image never parses untrusted input with libfoo
    expires: 2027-01-31
```

A package rule has no `vulnerability` and accepts every finding in the packages it matches — for an
upstream binary copied in at its newest release, whose findings are fixed only in builds not yet
released. It needs a `package` with a `location` or a `name`:

```yaml
ignore:
  - package:
      location: /usr/local/bin/some-tool
    reason: upstream binary at its newest release; its crates are fixed only in unreleased builds
    expires: 2027-04-01
  - package:
      name: "golang.org/x/.*"
      type: go-module
    reason: the x/ modules are vendored into binaries we do not build
    expires: 2027-04-01
```

`location` is a glob over the path syft recorded the package at (`/usr/local/bin/*`); `name` is an
anchored regex, so `golang.org/x/cry` matches nothing and `golang.org/x/.*` the whole family.
`version`, `type`, `language` and `upstream-name` narrow a package rule but cannot scope it alone.
The lint rejects a `package` key outside those six (`unknown package key: locaton`), because grype
drops unknown keys silently and the rule would widen; and it rejects a catch-all — a `location` made
only of `/`, `*` and `?`, or a `name` of `.*` or `.+`.

Lint a ledger with `mise exec -- bin/check-grype-ignores .grype.yaml`.

## Tool installation

The action installs this repository's pinned tools with
[mise-action](https://github.com/jdx/mise-action) on every run and keeps no cache.

`mise-action` caches the whole mise data directory under a key derived from the caller's workspace.
In a job that has already installed its own tools, that cache duplicates them, and restoring it
takes longer than installing: 5 s to install against 14 s to restore a 468 MB cache, measured on
2026-11-06 in a caller with twenty tools of its own. The key also does not follow this repository's
tool versions, so after a caller moves its pin the cache could restore stale tools. A caller that
wants caching sets it up in its own job.

The uncached install is authenticated: `mise-action`'s `github_token` input defaults to the job's
automatic token, and the action hands it to mise before installing. Release lookups and attestation
checks therefore count against the repository's authenticated rate limit, not the anonymous limit
shared by everything on the runner's IP address. No caller input is needed, and a read-only token is
enough.

## Running it locally

The action is a thin wrapper around `bin/sbom-scan`, which runs the same way from a checkout of this
repository with the same tool pins:

```sh
mise install
mise exec -- bin/sbom-scan [--out DIR] [--fail-on SEV] [--only-fixed|--all-fixes] \
  [--ignore FILE]… [--no-fail] [--public] SOURCE…
```

Sources may also come on stdin, one per line.

| exit | meaning |
|---|---|
| 0 | gate passed, or failed with `--no-fail` |
| 1 | gate failed, or a ledger failed the lint |
| 2 | usage |
| 3 | syft, grype or curl failed on any source (also with `--no-fail`) |
