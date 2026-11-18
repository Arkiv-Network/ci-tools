# sbom-store reference

The `sbom-store` action and `bin/sbom-store`. Inputs, outputs and a calling example are in the
[README](../README.md#sbom-store); the bucket layout, retention, lock and manifest schema are in
[`storage.md`](storage.md).

The action installs its tools the same way as `sbom-scan`, without a cache; see
[Tool installation](sbom-scan.md#tool-installation).

## Lines

Each line is `<key> <ref|-> <source>`: `key` is `sha256:<hex>` (an image digest, or the digest of
whatever else was scanned), `ref` the image reference or `-` for something that is not an image, and
`source` the `sbom-scan` source it is scanned from. Blank lines are skipped.

## missing

`missing` sends `HEAD sbom/<key>.syft.json.zst` and, when that is present, `HEAD
sbom/<key>.cdx.json.zst`, once per key, and prints the lines whose key lacks either (404): a key
whose earlier `put` stored only one of the two is scanned and stored again. A key with both (200) is
dropped. Any other status fails the step.

## get

`get --out DIR` sends `HEAD sbom/<key>.cdx.json.zst` and, when that is present, `GET
sbom/<key>.syft.json.zst`, once per key. A key with both (200) has its syft SBOM decompressed to
`DIR/sha256-<hex>.syft.json`, and every line with that key is printed with its source replaced by
`sbom:DIR/sha256-<hex>.syft.json`, `DIR` as given; `sbom-scan` then runs grype on that SBOM without
pulling the image. A key lacking either (404) has its lines printed unchanged and leaves no file in
`DIR`, the same rule `missing` applies. Lines come out in input order. Any other status, or an SBOM
that does not decompress, fails the step. `DIR` is created if absent and must not contain
whitespace. The action's `out-dir` input is `DIR`.

## put

`put` stores, for each line whose source is in `scan-dir/summary.json` without an `error`, the
zstd-compressed `sbom/<slug>.cdx.json`, `sbom/<slug>.syft.json` and `reports/<slug>.grype.json` as
`sbom/<key>.cdx.json.zst`, `sbom/<key>.syft.json.zst` and
`reports/<date>/<source>/<run-id>/<key>.grype.json.zst`. A line whose source was not scanned (its
SBOM was already stored) stores nothing, and a `scan-dir` without `summary.json` stores no objects.
A line whose source starts with `sbom:` — an SBOM `get` fetched from the bucket — stores only its
grype report: its SBOMs are already there.

Then it writes `runs/<date>/<source>/<run-id>/manifest.json` (schema v1, uncompressed): every line
whose ref is not `-`, its refs grouped by key and sorted. `<date>` is the UTC date, `<run-id>`
`$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT`, and the manifest's `run` comes from `GITHUB_REPOSITORY`,
`GITHUB_WORKFLOW`, `GITHUB_RUN_ID` and `GITHUB_SHA`.

With `--meta FILE` (the action's `meta` input), `FILE` is a JSON object
`{"sha256:<hex>": {"namespaces": […], "nodes": […]}}`, and each image in the manifest that has an
entry gains its `namespaces` and `nodes`, sorted and unique; entries for keys not in the manifest
are ignored. A `FILE` that cannot be read, is not such an object, or holds a non-string-array
`namespaces` or `nodes` is a usage error, before any request. Without it the images carry only
`refs`.

Put-once: each object is `HEAD`ed; a 404 is uploaded with `PUT`, a 200 is already present, and a
`409` on the `PUT` — the bucket lock refusing an overwrite — counts as present too. `put` prints one
line per object, `stored`, `present` or `failed` and the key, tries every object and the manifest,
and fails the step if any failed.

## Requests and credentials

Requests go through curl, signed with `--aws-sigv4 "aws:amz:auto:s3"`, to
`$R2_SBOM_ENDPOINT/$R2_SBOM_BUCKET/<key>`, with the `:` of `sha256:` sent as `%3A` because curl signs
the path as given.

| variable | meaning |
|---|---|
| `R2_SBOM_ENDPOINT` | the S3 endpoint, without the bucket |
| `R2_SBOM_BUCKET` | the bucket name |
| `R2_SBOM_ACCESS_KEY_ID` | the access key id; `put` needs a writer's |
| `R2_SBOM_SECRET_ACCESS_KEY` | that key's secret access key |

The four values come from the caller's environment, typically a GitHub Environment's secrets. The
key pair reaches curl as a config read from a pipe, so it is never on a command line, and it is
never printed.

## Running it locally

From a checkout of this repository:

```sh
mise exec -- bin/sbom-store missing <LINES
mise exec -- bin/sbom-store get --out DIR <LINES
mise exec -- bin/sbom-store put --scan-dir DIR --source NAME [--meta FILE] <LINES
```

| exit | meaning |
|---|---|
| 0 | done |
| 2 | usage (including an unreadable or malformed `--meta`), or a missing `R2_SBOM_*` (for `put`, also `GITHUB_*`) variable |
| 3 | an unexpected status (`missing`, `get`), an SBOM that does not decompress (`get`), or a failed object (`put`) |
