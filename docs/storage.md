# SBOM bucket contract

What a writer and a reader of the SBOM bucket rely on. `sbom-store` ([reference](sbom-store.md))
implements the writer's side.

One S3-compatible bucket (Cloudflare R2) holds every SBOM, grype report and run manifest. SBOMs are
keyed by digest and belong to no deployment: a builder publishing an image does not know where it
will run, and a bucket per environment would store the same digest once per environment.

## Layout

`<digest>` is written literally (`sha256:ab12…`), `<date>` is the UTC `YYYY-MM-DD` of the run, and
`<run-id>` is `$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT`. `<source>` names who ran: the repository for a
builder (`my-app`), the cluster for a scan of what a cluster runs (`cluster-a`). Every object is
zstd-compressed except the run manifest. The colon in `sha256:` is part of the key; a client that
signs the raw request path — curl's `--aws-sigv4` — must percent-encode it as `%3A`, which S3 SDKs
do on their own.

| key | content |
|---|---|
| `sbom/<digest>.cdx.json.zst` | CycloneDX SBOM of one image |
| `sbom/<digest>.syft.json.zst` | syft-native SBOM of the same image |
| `reports/<date>/<source>/<run-id>/<digest>.grype.json.zst` | one grype report |
| `runs/<date>/<source>/<run-id>/manifest.json` | the run manifest |

Every object is immutable: written once, never overwritten. An SBOM describes a digest, so the first
writer's copy is the copy. A report is a point-in-time match against the vulnerability data of its
run, so each run writes its own. The run id is in the key because a source runs more than once a
day, and under the lock a second write to the same key is refused. Listing `runs/*/<source>/`
answers what ran where and when.

## Retention

| prefix | lock | lifecycle delete |
|---|---|---|
| `sbom/` | 365 days | 365 days |
| `runs/` | 365 days | 365 days |
| `reports/` | 90 days | 90 days |
| whole bucket (`""`) | 90 days | 90 days |

The bucket-wide rules leave no object in the bucket unlocked. Lock rules outrank lifecycle rules,
and the longest matching lock wins, so effective retention is the lock's: the bucket-wide expiry
cannot reap an `sbom/` object before its 365-day lock ends. Nothing else can delete an object, so
the lifecycle is the retention policy and no pruner exists.

## What the lock guarantees

Cloudflare: "Bucket locks prevent the deletion and overwriting of objects". A refused write or
delete returns `409 ObjectLockedByBucketPolicy`, and the lock is checked before `If-None-Match`.
A writer stores each object put-once: `HEAD` the key, upload on a miss, and treat a `409` as already
present; then it writes its run manifest.

The lock binds every object operation, but not the bucket configuration: an identity that can edit
the bucket's configuration can remove a rule. A writer's credential cannot. Declaring the lock as
code makes a removed rule show as drift.

The lock bounds what a leaked writer credential can do — add objects, never overwrite or delete
one. It does not prevent first-writer-wins poisoning: a forged SBOM written ahead of the real one is
then held for a year. Keep the writer credential to the branches that publish.

## Manifest schema v1

```json
{
  "schema": 1,
  "source": "cluster-a",
  "generated_at": "2026-10-30T12:00:00Z",
  "run": {"repository": "example-org/my-app", "workflow": "…", "run_id": "…", "sha": "…"},
  "images": {
    "sha256:…": {"refs": ["ghcr.io/…:tag"], "namespaces": ["…"], "nodes": ["…"]}
  }
}
```

| field | meaning |
|---|---|
| `schema` | `1` |
| `source` | the cluster name for a cluster run, the repository name for a builder |
| `generated_at` | UTC timestamp of the run |
| `run` | the GitHub Actions run: repository, workflow, run id, commit SHA |
| `images` | per digest, its image refs sorted; `namespaces` and `nodes` only in cluster runs |
