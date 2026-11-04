# Working in ci-tools

Shared CI building blocks for Arkiv-Network repositories. Other repositories call them pinned by
commit SHA, so a change here reaches a caller only when that caller moves its pin.

| Where | What |
|---|---|
| `README.md` | The usage guide: how to call each action. Callers' docs link here. |
| `docs/` | Reference for each action and the storage contract; the README is the usage guide and links here. |
| `sbom-scan/` | The `sbom-scan` composite action. It only installs tools, runs `bin/sbom-scan` and uploads. |
| `sbom-store/` | The `sbom-store` composite action. It only installs tools and runs `bin/sbom-store`. |
| `bin/` | The scripts behind the actions, runnable from a shell; `bin/tests/` holds their tests. |
| `.mise.toml` | The pinned toolchain. Run everything through `mise exec -- <tool>`. |
| `.github/workflows/validate.yaml` | CI, including a self-test of the action. |

## This repository is public

Everything here is readable by anyone: no hostnames, private repository names, accepted-risk
reasoning or links into private repositories, in code, tests, docs or commit messages. Examples and
fixtures use generic names (`my-app`, `example-org`, `sbom-bucket`). The operator tooling that holds
credentials lives outside this repository.

## Local == CI

Logic lives in `bin/`, not in workflow or action YAML. A script writes `$GITHUB_OUTPUT` and
`$GITHUB_STEP_SUMMARY` only when they are set, so the same command works on a workstation, in a
caller's job and in a container. Every script change comes with a test under `bin/tests/`, and the
tests run offline with shims for the tools that reach the network.

Pin third-party actions by commit SHA with the version in a trailing comment
(`uses: owner/repo@<sha> # v4`).

## Merging

Squash-merge, so the PR title becomes the squashed subject — write it as the commit subject you
want. Never merge without watching CI to completion (`gh pr checks <n> --watch`) and seeing it
green. No exceptions for docs-only changes or one-liners. If a check the PR did not touch is red,
suspect breakage inherited from the base branch before debugging your own diff.

## Comments and docs

Every comment, doc and README is written for a reader who arrives after every issue, PR and
discussion around it has closed. Nothing may depend on the state of one: no "tracked in #N", "once
#N lands", "see the discussion on #N", "currently", "for now", "pending", "held until".

Comments must be timeless and terse: what the code does, sometimes briefly why, never how it got
there. No prior-state references, no dates, no PR numbers as narrative, no correction notices. When
a comment is wrong, write the correct one rather than annotating that it was wrong.

No local filesystem paths in committed files. Another repository is referenced by its GitHub URL.

No tool advertising anywhere: no "Generated with …" lines, no `Co-Authored-By` trailers for tools,
no badges or session links, in commit messages, PR bodies, issues, comments, code or docs.

## GitHub issues

An issue's title is an instruction, not a description: the imperative (`Scan pre-made SBOMs`) or a
*should* sentence (`An expired ignore rule should fail the scan`).

## Secrets

Run tools that need credentials under `mise exec -- <cmd>` so the values stay out of the terminal.
Never echo a secret to stdout or paste one into an issue, PR or commit.
