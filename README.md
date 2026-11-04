# ci-tools

Shared CI building blocks: two composite actions, `sbom-scan` (an SBOM and a vulnerability gate)
and `sbom-store` (put-once storage of what was scanned), whose scripts also run locally.

## Quick start

```yaml
      - uses: Arkiv-Network/ci-tools/sbom-scan@<commit sha>
        with:
          sources: docker:my-app:${{ github.sha }}
```

Pin a full commit SHA: the runner fetches this repository at that SHA, with no credential. Each
source gets a syft SBOM and a grype report, the job a Markdown step summary, and the step fails on
fixable High-and-above findings.

## sbom-scan

| input | default | meaning |
|---|---|---|
| `sources` | required | one source per line: `registry:<ref>@sha256:…`, `docker:<tag>`, `dir:<path>`, `oci-archive:<file>`, or `sbom:<path or https URL>` for a ready-made SBOM, which grype scans directly |
| `fail-on` | `high` | lowest severity that fails: `critical`, `high`, `medium`, `low`, `negligible` |
| `only-fixed` | `true` | count only findings with a fix available toward the gate |
| `ignore-file` | `` | the ignore ledger; when empty, `.grype.yaml` at the workspace root if it exists |
| `fail` | `true` | `false` = report only |
| `output-dir` | `sbom-scan` | where files land, relative to the workspace |
| `artifact-name` | `sbom-scan` | workflow artifact holding `output-dir`; empty = no upload |
| `public` | `false` | `true` for a public repository: ignored findings read `accepted`, the ledger stays out of `output-dir`, nothing is uploaded ([Public callers](#public-callers)) |

| output | meaning |
|---|---|
| `failed` | `true` when the gate found something — also with `fail: false` |
| `fixable-high` / `fixable-critical` | findings at High or above (Critical), not ignored, with a fix |
| `unfixed-high` / `unfixed-critical` | findings at High or above (Critical), not ignored, without a fix |
| `ignored-high` / `ignored-critical` | findings at High or above (Critical) accepted by an ignore rule, fixed or not |
| `kev` | findings on the CISA Known Exploited Vulnerabilities list, any severity, not ignored |
| `ignored-kev` | findings on the CISA KEV list, any severity, accepted by an ignore rule |
| `output-dir` / `summary-json` | absolute path of the output directory / of `summary.json` |

The gate counts non-ignored findings at or above `fail-on` (grype's severities) with a fix, when
`only-fixed`; unfixed ones are reported, not failed. It is decided from the report, not grype's exit
code. Output files, `summary.json` and exit codes: [`docs/sbom-scan.md`](docs/sbom-scan.md).

## Accepting risk

One ledger per repository: `ignore-file`, or `.grype.yaml` at the workspace root. A rule names a
`vulnerability`, a `package` (by `location` or `name`), or both, and needs a `reason` and an
`expires` at most 180 days ahead; an expired or malformed rule fails the scan. Lint with
`mise exec -- bin/check-grype-ignores .grype.yaml`; the full grammar (location globs, anchored-regex
names, rejected keys, catch-alls) is in [`docs/sbom-scan.md`](docs/sbom-scan.md#ignore-rules).

```yaml
ignore:
  - vulnerability: CVE-2024-12345
    reason: not reachable — the image never parses untrusted input with libfoo
    expires: 2027-01-31
  - package: {location: /usr/local/bin/some-tool}
    reason: upstream binary at its newest release
    expires: 2027-04-01
```

## Public callers

A public repository's logs, summary and artifacts are readable by anyone. `public: "true"` keeps
rule reasons out of them (the grype reports on disk keep them, for a private store). Keep the ledger
in a private repository, fetched with a read-only deploy key: public half on the ledger repository,
private half the caller's Actions secret. Fork PRs get no secrets, so there the scan is report-only:

```yaml
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        if: github.event.pull_request.head.repo.fork != true
        with:
          repository: example-org/sbom-ledgers
          ssh-key: ${{ secrets.SBOM_LEDGER_KEY }}
          path: ledger
      - uses: Arkiv-Network/ci-tools/sbom-scan@<commit sha>
        with:
          sources: docker:my-app:${{ github.sha }}
          ignore-file: ${{ github.event.pull_request.head.repo.fork != true && 'ledger/my-app.grype.yaml' || '' }}
          fail: ${{ github.event.pull_request.head.repo.fork != true }}
          public: "true"
```

## sbom-store

Stores SBOMs, grype reports and a run manifest in the SBOM bucket put-once, and lists the SBOMs the
bucket lacks, so only those are scanned. The job uses a GitHub Environment restricted to `main`:

```yaml
    environment: sbom-writer
    env:
      R2_SBOM_ENDPOINT: ${{ secrets.R2_SBOM_ENDPOINT }}
      R2_SBOM_BUCKET: ${{ secrets.R2_SBOM_BUCKET }}
      R2_SBOM_ACCESS_KEY_ID: ${{ secrets.R2_SBOM_ACCESS_KEY_ID }}
      R2_SBOM_SECRET_ACCESS_KEY: ${{ secrets.R2_SBOM_SECRET_ACCESS_KEY }}
    steps:
      - id: missing
        uses: Arkiv-Network/ci-tools/sbom-store@<commit sha>
        with: {mode: missing, lines: "${{ steps.inventory.outputs.lines }}"}
      # sbom-scan with fail: false over the third field of each missing line, then:
      - uses: Arkiv-Network/ci-tools/sbom-store@<commit sha>
        with: {mode: put, source: my-app, lines: "${{ steps.inventory.outputs.lines }}"}
```

| input | default | meaning |
|---|---|---|
| `mode` | required | `missing` or `put` |
| `lines` | required | one `<key> <ref\|-> <source>` per line: `sha256:<hex>`, the image ref or `-`, the `sbom-scan` source |
| `scan-dir` | `sbom-scan` | `put`: the `sbom-scan` output directory |
| `source` | `` | `put`: the run's source name — the repository for a builder, the cluster for a cluster scan |

Output `lines` (`missing`): the input lines whose SBOM is absent from the bucket.
Bucket contract: [`docs/storage.md`](docs/storage.md). `missing`, `put`, exit codes: [`docs/sbom-store.md`](docs/sbom-store.md).

## Running locally

```sh
mise install
mise exec -- bin/sbom-scan [--out DIR] [--fail-on SEV] [--ignore FILE]… [--no-fail] SOURCE…
mise exec -- bin/sbom-store missing <LINES
mise exec -- bash bin/tests/<name>.test.sh
```

## License

Licensed under either of Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)) or MIT
license ([`LICENSE-MIT`](LICENSE-MIT)) at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or conditions.
