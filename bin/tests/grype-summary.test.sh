#!/usr/bin/env bash
# Fixture tests for bin/grype-summary over a real grype report excerpt (alpine 3.14.0, trimmed;
# one KEV entry grafted on): summary.json shape and totals, the gate under each option, the
# Markdown report, and the $GITHUB_OUTPUT / $GITHUB_STEP_SUMMARY files. A synthetic report with
# ignored matches at Critical and High exercises the Critical and ignored totals.
#
# Needs jq on PATH: run under `mise exec --`.
#
#   bin/tests/grype-summary.test.sh   # exit 0 = all pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../grype-summary"
command -v jq >/dev/null || { echo "these tests need jq on PATH — run: mise exec -- bash $0" >&2; exit 2; }
TMP="$(mktemp -d "${SCRATCH_DIR:-/tmp}/grype-summary-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
ok()  { echo "ok   - $1"; pass=$((pass + 1)); }
bad() { echo "FAIL - $1"; fail=$((fail + 1)); }

HEX="$(printf 'a%.0s' $(seq 64))"
SRC="registry:example.com/app:1@sha256:$HEX"
OUTDIR="$TMP/out"
mkdir -p "$OUTDIR/reports"
cp "$HERE/fixtures/alpine.grype.json" "$OUTDIR/reports/sha256-$HEX.grype.json"
ENVV=()
run() { OUT="$(env -i PATH="$PATH" HOME="$HOME" ${ENVV[@]+"${ENVV[@]}"} python3 "$SCRIPT" "$@" 2>&1)"; return $?; }
S="$OUTDIR/summary.json"

# 1) default gate (high, only fixed) fails on the fixed Critical/High matches
run "$OUTDIR" "sha256-$HEX=$SRC"
[ $? -eq 1 ] && ok "default gate fails with exit 1" || bad "default gate should exit 1: $OUT"
[ "$(jq -c .totals "$S")" = '{"fixable_high":3,"fixable_critical":2,"unfixed_high":3,"unfixed_critical":2,"ignored_high":1,"ignored_critical":0,"kev":1,"ignored_kev":0,"errors":0}' ] \
  && ok "totals: 3 fixable, 3 unfixed, 1 ignored, 1 KEV" || bad "wrong totals: $(jq -c .totals "$S")"
[ "$(jq -c .gate "$S")" = '{"fail_on":"high","only_fixed":true,"failed":true}' ] \
  && ok "gate recorded" || bad "wrong gate: $(jq -c .gate "$S")"
[ "$(jq -r '.sources[0] | [.source, .slug, .digest] | join(" ")' "$S")" = "$SRC sha256-$HEX sha256:$HEX" ] \
  && ok "source, slug and digest recorded" || bad "wrong source block: $(jq -c '.sources[0] | del(.counts, .findings)' "$S")"

# 2) counts cover every severity of the non-ignored matches; empty fix state reads as unknown
[ "$(jq '[.sources[0].counts[].count] | add' "$S")" = 9 ] && ok "counts sum to the 9 active matches" \
  || bad "wrong counts: $(jq -c '.sources[0].counts' "$S")"
jq -e '.sources[0].counts | any(.severity == "Low")' "$S" >/dev/null && ok "counts include Low" || bad "Low missing from counts"
jq -e '.sources[0].counts | any(.fix_state == "") | not' "$S" >/dev/null && ok "no empty fix_state" || bad "empty fix_state leaked"

# 3) findings: Medium and above, ignored ones included and attributed
jq -e '.sources[0].findings | length == 9 and all(.severity != "Low")' "$S" >/dev/null \
  && ok "findings hold the Medium+ matches, ignored included" || bad "wrong findings: $(jq -c '[.sources[0].findings[].id]' "$S")"
[ "$(jq -r '.sources[0].findings[] | select(.id == "CVE-2022-28391") | .ignored_by' "$S")" = "fixture rule" ] \
  && ok "ignored finding names its rule" || bad "ignored_by missing"
jq -e '.sources[0].findings[] | select(.id == "CVE-2021-36159") | .kev and .fix_versions == ["2.12.6-r0"] and .epss > 0' "$S" >/dev/null \
  && ok "KEV, fix versions and EPSS carried" || bad "KEV finding wrong"

# 4) gate options
run --fail-on critical "$OUTDIR" "sha256-$HEX=$SRC"
[ $? -eq 1 ] && echo "$OUT" | grep -q '2 finding(s) at critical' && ok "fail-on critical counts the 2 fixed Criticals" \
  || bad "fail-on critical: $OUT"
run --fail-on critical --all-fixes "$OUTDIR" "sha256-$HEX=$SRC"
echo "$OUT" | grep -q '4 finding(s) at critical or above, fixed or not' && ok "--all-fixes counts unfixed too" \
  || bad "--all-fixes: $OUT"
run --fail-on medium "$OUTDIR" "sha256-$HEX=$SRC"
echo "$OUT" | grep -q '4 finding(s) at medium' && ok "fail-on medium adds the fixed Medium" || bad "fail-on medium: $OUT"
run --no-fail "$OUTDIR" "sha256-$HEX=$SRC"
[ $? -eq 0 ] && jq -e '.gate.failed' "$S" >/dev/null && ok "--no-fail exits 0 and still records failed" \
  || bad "--no-fail: $OUT"

# 5) a report with nothing at the threshold passes
mkdir -p "$TMP/clean/reports"
jq '.matches |= map(select(.vulnerability.fix.state != "fixed"))' "$HERE/fixtures/alpine.grype.json" >"$TMP/clean/reports/c.grype.json"
run "$TMP/clean" "c=dir:."
[ $? -eq 0 ] && echo "$OUT" | grep -q 'Gate passed' && [ "$(jq .sources[0].digest "$TMP/clean/summary.json")" = null ] \
  && ok "nothing fixable passes, digest null without @sha256" || bad "clean report: $OUT"

# 6) Markdown: table row, unfixed list, totals line
run "$OUTDIR" "sha256-$HEX=$SRC"
echo "$OUT" | grep -qF '| CVE-2021-36159 | apk-tools | 2.12.5-r1 | Critical | 2.12.6-r0 | 2.6% | yes |  |' \
  && ok "table row rendered" || bad "table row missing: $OUT"
echo "$OUT" | grep -qF -- '- CVE-2022-48174 in busybox 1.33.1-r2 (Critical, unknown)' \
  && ok "unfixed High+ listed" || bad "unfixed list missing: $OUT"
echo "$OUT" | grep -qF '**Totals:** 3 fixable High+ (2 Critical), 3 unfixed High+ (2 Critical), 1 ignored High+ (0 Critical), 1 on CISA KEV (0 ignored).' \
  && ok "totals line rendered" || bad "totals line missing: $OUT"

# 7) GitHub files are written only when set
ENVV=(GITHUB_OUTPUT="$TMP/gh-out" GITHUB_STEP_SUMMARY="$TMP/gh-summary")
run "$OUTDIR" "sha256-$HEX=$SRC"
grep -qx 'failed=true' "$TMP/gh-out" && grep -qx 'fixable-high=3' "$TMP/gh-out" && grep -qx 'unfixed-high=3' "$TMP/gh-out" \
  && grep -qx 'kev=1' "$TMP/gh-out" && grep -qx 'ignored-kev=0' "$TMP/gh-out" && grep -qx "summary-json=$S" "$TMP/gh-out" && grep -qx "output-dir=$OUTDIR" "$TMP/gh-out" \
  && ok "outputs written to GITHUB_OUTPUT" || bad "wrong outputs: $(cat "$TMP/gh-out")"
grep -q '^## SBOM scan' "$TMP/gh-summary" && ok "Markdown appended to GITHUB_STEP_SUMMARY" || bad "step summary missing"
ENVV=()

# 8) ignored matches at Critical and High, accepted by a package rule and a vulnerability rule, are
# counted apart from the active ones; an ignored Medium counts in no High total, and an ignored KEV
# entry counts in ignored_kev, not kev
mkdir -p "$TMP/ign/reports"
cp "$HERE/fixtures/ignored.grype.json" "$TMP/ign/reports/i.grype.json"
ENVV=(GITHUB_OUTPUT="$TMP/ign-out")
run --no-fail "$TMP/ign" "i=dir:."
ENVV=()
[ "$(jq -c .totals "$TMP/ign/summary.json")" = '{"fixable_high":2,"fixable_critical":1,"unfixed_high":4,"unfixed_critical":3,"ignored_high":6,"ignored_critical":5,"kev":1,"ignored_kev":1,"errors":0}' ] \
  && ok "summary.json: the six counts, KEV and ignored KEV" || bad "wrong totals: $(jq -c .totals "$TMP/ign/summary.json")"
[ "$(grep -E '^(fixable|unfixed|ignored)-(high|critical)=|^(ignored-)?kev=' "$TMP/ign-out" | tr '\n' ' ')" \
  = 'fixable-high=2 fixable-critical=1 unfixed-high=4 unfixed-critical=3 ignored-high=6 ignored-critical=5 kev=1 ignored-kev=1 ' ] \
  && ok "GITHUB_OUTPUT: the six counts, KEV and ignored KEV" || bad "wrong count outputs: $(cat "$TMP/ign-out")"
echo "$OUT" | grep -qF '**Totals:** 2 fixable High+ (1 Critical), 4 unfixed High+ (3 Critical), 6 ignored High+ (5 Critical), 1 on CISA KEV (1 ignored).' \
  && ok "totals line carries the Critical and ignored counts" || bad "totals line: $OUT"
echo "$OUT" | grep -qF '| CVE-2000-0102 | tool | 1.0.0 | Critical | not-fixed |  |  | upstream binary at its newest release |' \
  && ok "package rule's reason in the ignored by column" || bad "package-rule row missing: $OUT"

# 9) --public: every ignored finding reads `accepted` in summary.json and the Markdown, no rule's
# reason appears, active findings keep ignored_by null, and the totals do not move
cp "$TMP/ign/summary.json" "$TMP/ign-private.json"
run --no-fail --public "$TMP/ign" "i=dir:."
PS="$TMP/ign/summary.json"
jq -e '[.sources[].findings[] | select(.id | IN($ids[]))] | length > 0 and all(.ignored_by == "accepted")' \
  --argjson ids "$(jq -c '[.ignoredMatches[].vulnerability.id]' "$HERE/fixtures/ignored.grype.json")" "$PS" >/dev/null \
  && ok "--public: every ignored finding reads accepted" || bad "--public ignored_by: $(jq -c '[.sources[].findings[] | {id, ignored_by}]' "$PS")"
[ "$(jq -c '[.sources[].findings[] | select(.ignored_by != "accepted") | .ignored_by] | unique' "$PS")" = '[null]' ] \
  && ok "--public: active findings keep ignored_by null" || bad "--public active: $(jq -c '[.sources[].findings[] | {id, ignored_by}]' "$PS")"
[ "$(jq -c .totals "$PS")" = "$(jq -c .totals "$TMP/ign-private.json")" ] && ok "--public: totals unchanged" \
  || bad "--public totals: $(jq -c .totals "$PS")"
echo "$OUT" | grep -qF '| CVE-2000-0102 | tool | 1.0.0 | Critical | not-fixed |  |  | accepted |' \
  && ok "--public: the ignored by column reads accepted" || bad "--public row: $OUT"
! grep -qF -e 'upstream binary at its newest release' -e 'not reachable' <<<"$OUT$(cat "$PS")" \
  && ok "--public: no rule's reason in the Markdown or summary.json" || bad "--public leaked a reason: $OUT"

# 10) a source with errors/<slug>.txt carries the message, no findings, and counts in totals.errors
mkdir -p "$TMP/err/reports" "$TMP/err/errors"
cp "$HERE/fixtures/alpine.grype.json" "$TMP/err/reports/good.grype.json"
echo "syft failed on docker:bad" >"$TMP/err/errors/bad.txt"
run --no-fail "$TMP/err" "good=docker:good" "bad=docker:bad"
jq -e '.totals.errors == 1 and (.sources[1] | .error == "syft failed on docker:bad" and .findings == [] and .counts == [])
  and (.sources[0] | has("error") | not)' "$TMP/err/summary.json" >/dev/null \
  && ok "errored source recorded with its message and counted" || bad "errored source: $(jq -c . "$TMP/err/summary.json")"
echo "$OUT" | grep -qF '**Scan failed:** syft failed on docker:bad' && echo "$OUT" | grep -qF -- '- `docker:bad`: syft failed on docker:bad' \
  && ok "errored source listed in the Markdown" || bad "errors missing from Markdown: $OUT"

# 11) usage and unreadable reports exit 2
run "$OUTDIR" "missing=$SRC"
[ $? -eq 2 ] && echo "$OUT" | grep -q 'cannot read' && ok "missing report exits 2" || bad "missing report: $OUT"
run "$OUTDIR" "no-separator"
[ $? -eq 2 ] && ok "malformed SLUG=SOURCE exits 2" || bad "malformed pair: $OUT"
run --fail-on severe "$OUTDIR" "sha256-$HEX=$SRC"
[ $? -eq 2 ] && ok "unknown severity exits 2" || bad "unknown severity: $OUT"

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
