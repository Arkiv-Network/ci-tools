#!/usr/bin/env bash
# Fixture tests for bin/sbom-scan, offline. The real scripts run from a throwaway copy of the
# repository, where bin/check-grype-ignores and bin/grype-summary are wrapped to log their arguments;
# syft, grype and curl are shims that log their arguments, write placeholder SBOMs, and answer with
# the grype fixture report.
#
# Needs yq and jq on PATH: run under `mise exec --`.
#
#   bin/tests/sbom-scan.test.sh   # exit 0 = all pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for t in yq jq; do
  command -v "$t" >/dev/null || { echo "these tests need $t on PATH — run: mise exec -- bash $0" >&2; exit 2; }
done
TMP="$(mktemp -d "${SCRATCH_DIR:-/tmp}/sbom-scan-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
ok()  { echo "ok   - $1"; pass=$((pass + 1)); }
bad() { echo "FAIL - $1"; fail=$((fail + 1)); }

REPO="$TMP/repo"
mkdir -p "$REPO/bin"
cp "$HERE/../sbom-scan" "$REPO/bin/"
for w in check-grype-ignores grype-summary; do
  cp "$HERE/../$w" "$REPO/bin/$w.real"
  cat >"$REPO/bin/$w" <<FAKE
#!/usr/bin/env bash
echo "$w \$*" >>"\$LOG"
exec "\$(dirname "\$0")/$w.real" "\$@"
FAKE
  chmod +x "$REPO/bin/$w"
done
EXP="$(date -u -d '+30 days' +%F)"
CLEAN="$TMP/clean.grype.json"
jq '.matches |= map(select(.vulnerability.fix.state != "fixed"))' "$HERE/fixtures/alpine.grype.json" >"$CLEAN"

# ── shims ──────────────────────────────────────────────────────────────────────
BIN="$TMP/bin"
mkdir -p "$BIN"
cat >"$BIN/syft" <<'FAKE'
#!/usr/bin/env bash
echo "syft $*" >>"$LOG"
[ "${SYFT_RC:-0}" -eq 0 ] || exit "$SYFT_RC"
case "$1" in *broken*) echo "syft: cannot pull $1" >&2; exit 1 ;; esac
while [ $# -gt 0 ]; do [ "$1" = -o ] && echo '{}' >"${2#*=}"; shift; done
FAKE
cat >"$BIN/grype" <<'FAKE'
#!/usr/bin/env bash
echo "grype $*" >>"$LOG"
cp "$2" "$LOG.config"
cat "$GRYPE_REPORT"
FAKE
cat >"$BIN/curl" <<'FAKE'
#!/usr/bin/env bash
echo "curl $*" >>"$LOG"
url="${*: -1}"
case "$url" in *missing*) exit 22 ;; esac
echo '{"spdxVersion":"SPDX-2.3"}' >"$3"
FAKE
chmod +x "$BIN"/*

HEX="$(printf 'b%.0s' $(seq 64))"
IMG="registry:example.com/app:1@sha256:$HEX"
export LOG="$TMP/log" GRYPE_REPORT="$HERE/fixtures/alpine.grype.json"
run() {
  : >"$LOG"
  OUT="$(cd "$TMP" && env -i PATH="$BIN:$PATH" HOME="$HOME" LOG="$LOG" GRYPE_REPORT="$GRYPE_REPORT" \
    ${SYFT_RC:+SYFT_RC="$SYFT_RC"} "$REPO/bin/sbom-scan" "$@" 2>&1)"
}

# 1) an image by digest: SBOMs, report and summary under the sha256 slug; the gate fails
run --out o1 "$IMG" </dev/null
rc=$?
[ $rc -eq 1 ] && ok "fixable High+ fails the gate with exit 1" || bad "expected exit 1, got $rc: $OUT"
for f in "sbom/sha256-$HEX.cdx.json" "sbom/sha256-$HEX.syft.json" "reports/sha256-$HEX.grype.json" summary.json grype.yaml; do
  [ -s "$TMP/o1/$f" ] && ok "wrote $f" || bad "missing $f"
done
grep -q "^syft $IMG -o cyclonedx-json@1.6=o1/sbom/sha256-$HEX.cdx.json -o syft-json=o1/sbom/sha256-$HEX.syft.json" "$LOG" \
  && ok "syft writes CycloneDX 1.6 and syft JSON" || bad "wrong syft call: $(cat "$LOG")"
grep -q "^grype -c o1/grype.yaml sbom:o1/sbom/sha256-$HEX.syft.json -o json" "$LOG" \
  && ok "grype scans the syft SBOM with the merged ledger" || bad "wrong grype call: $(cat "$LOG")"
[ "$(jq -r '.sources[0].digest' "$TMP/o1/summary.json")" = "sha256:$HEX" ] && ok "digest in summary" || bad "digest missing"
echo "$OUT" | grep -q 'Gate FAILED' && ok "Markdown report printed" || bad "no report: $OUT"

# 2) no --ignore: nothing is linted and the scan runs on an empty ledger
run --out o2e "$IMG" </dev/null
! grep -q '^check-grype-ignores' "$LOG" && ok "no ledger, no lint" || bad "lint called without a ledger: $(cat "$LOG")"
[ "$(yq -o=json -I0 . "$TMP/o2e/grype.yaml" | jq -c .)" = '{"ignore":[]}' ] \
  && ok "no ledger merges to ignore: []" || bad "wrong empty ledger: $(cat "$TMP/o2e/grype.yaml")"

# 3) ledger merge: each --ignore file linted, ignore lists concatenated in order, other keys from the
# first file only
cat >"$TMP/first.yaml" <<YAML
check-for-app-update: false
ignore:
  - vulnerability: CVE-FIRST-1
    reason: first rule
    expires: $EXP
YAML
cat >"$TMP/second.yaml" <<YAML
fail-on-severity: low
ignore:
  - vulnerability: CVE-SECOND-1
    reason: second rule
    expires: $EXP
YAML
: >"$TMP/empty.yaml"
run --out o2 --ignore first.yaml --ignore second.yaml --ignore empty.yaml "$IMG" </dev/null
grep -qx 'check-grype-ignores first.yaml second.yaml empty.yaml' "$LOG" \
  && ok "every ledger linted" || bad "wrong lint call: $(cat "$LOG")"
[ "$(yq -o=json -I0 '[.ignore[].vulnerability]' "$LOG.config")" = '["CVE-FIRST-1","CVE-SECOND-1"]' ] \
  && ok "ignore lists concatenated in order" || bad "wrong merged rules: $(cat "$LOG.config")"
[ "$(yq '.check-for-app-update' "$LOG.config")" = false ] && [ "$(yq '.fail-on-severity' "$LOG.config")" = null ] \
  && ok "other keys come from the first ledger only" || bad "wrong merged keys: $(cat "$LOG.config")"

# 4) a ledger failing the lint stops the run with exit 1 before any scan
run --out o3 --ignore "$HERE/fixtures/ignore-expired.yaml" "$IMG" </dev/null
rc=$?
[ $rc -eq 1 ] && echo "$OUT" | grep -q 'expired on 2020-01-01' && ! grep -qE '^(syft|grype) ' "$LOG" \
  && ok "lint failure exits 1 with the lint output, nothing scanned" || bad "lint failure: rc=$rc $OUT"

# 5) sbom: a local file is copied and scanned directly, no syft
mkdir -p "$TMP/x/y"
echo '{"spdxVersion":"SPDX-2.3"}' >"$TMP/x/y/talos-amd64.spdx.json"
GRYPE_REPORT="$CLEAN" run --out o4 sbom:x/y/talos-amd64.spdx.json </dev/null
rc=$?
[ $rc -eq 0 ] && ok "nothing fixable passes with exit 0" || bad "expected exit 0, got $rc: $OUT"
[ -s "$TMP/o4/sbom/sbom-x-y-talos-amd64.spdx.json" ] && ! grep -q '^syft' "$LOG" \
  && grep -q '^grype -c o4/grype.yaml sbom:o4/sbom/sbom-x-y-talos-amd64.spdx.json ' "$LOG" \
  && ok "local SBOM copied and scanned without syft" || bad "sbom: path: $(ls -R "$TMP/o4") $(cat "$LOG")"

# 6) sbom: an https URL is fetched with curl -fsSL; a failed fetch exits 3
URL=https://example.com/releases/v1/talos-amd64.spdx.json
GRYPE_REPORT="$CLEAN" run --out o5 "sbom:$URL" </dev/null
S5="sbom-https---example.com-releases-v1-talos-amd64.spdx.json"
grep -q "^curl -fsSL -o o5/sbom/$S5 $URL" "$LOG" && [ -s "$TMP/o5/sbom/$S5" ] \
  && ok "https SBOM fetched with curl" || bad "https fetch: $(cat "$LOG")"
run --out o5 "sbom:https://example.com/missing.json" </dev/null
[ $? -eq 3 ] && ok "failed fetch exits 3" || bad "failed fetch: $OUT"

# 7) sources from stdin, blank lines skipped; slug of a tag replaces every other character with -
printf '  docker:my/app:dev  \n\n' | run --out o6 --no-fail
rc=$?
[ $rc -eq 0 ] && ok "--no-fail exits 0" || bad "--no-fail: rc=$rc $OUT"
[ -s "$TMP/o6/reports/docker-my-app-dev.grype.json" ] && grep -q '^syft docker:my/app:dev ' "$LOG" \
  && ok "stdin source read and slugged" || bad "stdin source: $(ls -R "$TMP/o6") $(cat "$LOG")"
jq -e '.gate.failed and .sources[0].digest == null' "$TMP/o6/summary.json" >/dev/null \
  && ok "--no-fail still records failed" || bad "--no-fail summary wrong"

# 8) a syft failure exits 3
SYFT_RC=1 run --out o7 "$IMG" </dev/null
[ $? -eq 3 ] && echo "$OUT" | grep -q 'syft failed' && ok "syft failure exits 3" || bad "syft failure: $OUT"

# 9) a failing source between two good ones: both good ones scanned, the error recorded, exit 3
run --out o8 docker:one:1 docker:broken:1 docker:two:1 </dev/null
rc=$?
[ $rc -eq 3 ] && ok "a failed source exits 3 even though the gate failed too" || bad "expected exit 3, got $rc: $OUT"
[ -s "$TMP/o8/reports/docker-one-1.grype.json" ] && [ -s "$TMP/o8/reports/docker-two-1.grype.json" ] \
  && ok "the sources around the failed one are scanned" || bad "good sources not scanned: $(ls -R "$TMP/o8")"
jq -e '.totals.errors == 1 and ([.sources[].source] == ["docker:one:1", "docker:broken:1", "docker:two:1"])
  and (.sources[1].error == "syft failed on docker:broken:1")' "$TMP/o8/summary.json" >/dev/null \
  && ok "summary.json carries the error and totals.errors" || bad "summary: $(jq -c '[.totals, [.sources[] | {source, error}]]' "$TMP/o8/summary.json")"
echo "$OUT" | grep -qF -- '- `docker:broken:1`: syft failed on docker:broken:1' && ok "error listed in the report" \
  || bad "error not in the report: $OUT"
GRYPE_REPORT="$CLEAN" run --out o8 --no-fail docker:one:1 docker:broken:1 </dev/null
[ $? -eq 3 ] && ok "--no-fail does not suppress exit 3" || bad "--no-fail with an error: $OUT"
GRYPE_REPORT="$CLEAN" run --out o8 docker:one:1 </dev/null
[ $? -eq 0 ] && [ ! -e "$TMP/o8/errors/docker-broken-1.txt" ] && jq -e '.totals.errors == 0' "$TMP/o8/summary.json" >/dev/null \
  && ok "a rerun into the same directory drops stale errors" || bad "stale errors: $OUT"

# 10) --public: the merged ledger lives in a temporary file outside DIR, gone after the run, a
# grype.yaml left by an earlier run is removed, and grype-summary runs with --public
run --out o9 --ignore first.yaml "$IMG" </dev/null
[ -s "$TMP/o9/grype.yaml" ] && ! grep -q '^grype-summary .*--public' "$LOG" \
  && ok "without --public the ledger lands in DIR" || bad "default ledger: $(ls "$TMP/o9") $(cat "$LOG")"
run --out o9 --public --ignore first.yaml "$IMG" </dev/null
cfg="$(sed -n 's/^grype -c \([^ ]*\) .*/\1/p' "$LOG" | head -n1)"
[ -n "$cfg" ] && [[ "$cfg" != o9/* && "$cfg" != "$TMP/o9/"* ]] && ok "--public ledger outside the output directory" \
  || bad "--public ledger path: $(cat "$LOG")"
[[ "$cfg" == *.yaml ]] && ok "--public ledger has a .yaml extension, which grype needs to load it" \
  || bad "--public ledger path lacks .yaml: $cfg"
[ "$(yq -o=json -I0 '[.ignore[].vulnerability]' "$LOG.config")" = '["CVE-FIRST-1"]' ] \
  && ok "--public ledger carries the rules" || bad "--public ledger: $(cat "$LOG.config")"
[ ! -e "$TMP/o9/grype.yaml" ] && ok "--public leaves no grype.yaml in DIR" || bad "--public left $TMP/o9/grype.yaml"
[ -n "$cfg" ] && [ ! -e "$cfg" ] && ok "--public ledger removed after the run" || bad "--public ledger left at $cfg"
grep -q '^grype-summary .*--public' "$LOG" && ok "grype-summary called with --public" || bad "grype-summary call: $(cat "$LOG")"

# 11) usage errors exit 2
run </dev/null;                 [ $? -eq 2 ] && ok "no sources exits 2" || bad "no sources: $OUT"
run --fail-on severe "$IMG";    [ $? -eq 2 ] && ok "bad --fail-on exits 2" || bad "bad --fail-on: $OUT"
run --bogus "$IMG";             [ $? -eq 2 ] && ok "unknown option exits 2" || bad "unknown option: $OUT"
run --ignore nope.yaml "$IMG";  [ $? -eq 2 ] && ok "missing --ignore file exits 2" || bad "missing ledger: $OUT"
run sbom:nope.json </dev/null;  [ $? -eq 2 ] && ok "missing SBOM file exits 2" || bad "missing SBOM: $OUT"

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
