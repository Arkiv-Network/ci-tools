#!/usr/bin/env bash
# Fixture tests for bin/sbom-store, offline. curl is a shim that logs each request's method, URL,
# arguments and -K config, keeps every uploaded body, and answers with the HTTP status the test's rules give for
# that method and URL (default: HEAD 404, PUT 200).
#
# Needs jq and zstd on PATH: run under `mise exec --`.
#
#   bin/tests/sbom-store.test.sh   # exit 0 = all pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for t in jq zstd; do
  command -v "$t" >/dev/null || { echo "these tests need $t on PATH — run: mise exec -- bash $0" >&2; exit 2; }
done
TMP="$(mktemp -d "${SCRATCH_DIR:-/tmp}/sbom-store-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
ok()  { echo "ok   - $1"; pass=$((pass + 1)); }
bad() { echo "FAIL - $1"; fail=$((fail + 1)); }

# ── shims ──────────────────────────────────────────────────────────────────────
BIN="$TMP/bin"
mkdir -p "$BIN"
cat >"$BIN/curl" <<'FAKE'
#!/usr/bin/env bash
echo "args $*" >>"$LOG"
method=GET body=""
args=("$@")
for i in "${!args[@]}"; do
  case "${args[$i]}" in
    -I) method=HEAD ;;
    -T) method=PUT body="${args[$((i + 1))]}" ;;
    -K) echo "config $(cat "${args[$((i + 1))]}")" >>"$LOG" ;;
  esac
done
url="${*: -1}"
echo "$method $url" >>"$LOG"
code=404
[ "$method" = PUT ] && code=200
while read -r m pattern c; do
  [ "$m" = "$method" ] && [[ "$url" == *$pattern* ]] && { code="$c"; break; }
done <"$RULES"
if [ "$method" = PUT ] && [ "$code" = 200 ]; then
  dest="$STORE/${url#*/sbom-bucket/}"
  mkdir -p "${dest%/*}" && cp "$body" "$dest"
fi
printf '%s' "$code"
FAKE
chmod +x "$BIN"/*

A="sha256:$(printf 'a%.0s' $(seq 64))" B="sha256:$(printf 'b%.0s' $(seq 64))"
C="sha256:$(printf 'c%.0s' $(seq 64))" D="sha256:$(printf 'd%.0s' $(seq 64))"
SA="registry:ghcr.io/x/a@$A" SB="registry:ghcr.io/x/b@$B" SC="registry:ghcr.io/x/c@$C" SD="dir:examples/cluster-a"
LINES="$A ghcr.io/x/a:2 $SA
$A ghcr.io/x/a:1 $SA

$B ghcr.io/x/b:1 $SB
$C ghcr.io/x/c:1 $SC
$D - $SD
"
# A and D scanned, B failed to scan, C not scanned (already stored).
SCAN="$TMP/scan"
mkdir -p "$SCAN/sbom" "$SCAN/reports"
for s in "sha256-${A#sha256:}" dir-examples-cluster-a; do
  echo "{\"cdx\":\"$s\"}" >"$SCAN/sbom/$s.cdx.json"
  echo "{\"syft\":\"$s\"}" >"$SCAN/sbom/$s.syft.json"
  echo "{\"grype\":\"$s\"}" >"$SCAN/reports/$s.grype.json"
done
jq -n --arg a "$SA" --arg b "$SB" --arg d "$SD" --arg sa "sha256-${A#sha256:}" '{sources: [
  {source: $a, slug: $sa}, {source: $b, slug: "sha256-b", error: "syft failed on \($b)"},
  {source: $d, slug: "dir-examples-cluster-a"}]}' >"$SCAN/summary.json"

KEY_ID=AKIDtestkeyid0001 SECRET=s3cr3t-value-never-printed
DATE="$(date -u +%F)" RUN=runs/"$(date -u +%F)"/my-app/42-2
export LOG="$TMP/log" RULES="$TMP/rules" STORE="$TMP/store"
GH=(GITHUB_REPOSITORY=example-org/my-app GITHUB_WORKFLOW=SBOM GITHUB_RUN_ID=42 GITHUB_RUN_ATTEMPT=2
  GITHUB_SHA=0123abc)
R2=(R2_SBOM_ENDPOINT=https://acct.eu.r2.example.com/ R2_SBOM_BUCKET=sbom-bucket
  R2_SBOM_ACCESS_KEY_ID="$KEY_ID" R2_SBOM_SECRET_ACCESS_KEY="$SECRET")
EXTRA=()
# run INPUT ARGS… — rules come from $RULES, written before the call
run() {
  local input="$1"; shift
  : >"$LOG"; rm -rf "$STORE"
  OUT="$(printf '%s' "$input" | env -i PATH="$BIN:$PATH" HOME="$HOME" LOG="$LOG" RULES="$RULES" STORE="$STORE" \
    ${R2[@]+"${R2[@]}"} ${GH[@]+"${GH[@]}"} ${EXTRA[@]+"${EXTRA[@]}"} "$HERE/../sbom-store" "$@" 2>&1)"
}
rules() { printf '%s\n' "$@" >"$RULES"; }
has() { grep -qFx -- "$1" <<<"$OUT"; }
no_secret() { ! grep -qF -e "$KEY_ID" -e "$SECRET" <<<"$OUT"; }

# 1) put: scanned keys stored, failed and unscanned ones not, manifest written
rules
run "$LINES" put --scan-dir "$SCAN" --source my-app
rc=$?
[ $rc -eq 0 ] && ok "put exits 0" || bad "expected exit 0, got $rc: $OUT"
want=("stored sbom/$A.cdx.json.zst" "stored sbom/$A.syft.json.zst"
  "stored reports/$DATE/my-app/42-2/$A.grype.json.zst" "stored sbom/$D.cdx.json.zst"
  "stored sbom/$D.syft.json.zst" "stored reports/$DATE/my-app/42-2/$D.grype.json.zst" "stored $RUN/manifest.json")
missing_line=""
for w in "${want[@]}"; do has "$w" || missing_line="$w"; done
[ -z "$missing_line" ] && [ "$(wc -l <<<"$OUT")" -eq 7 ] && ok "one stored line per object, A and D only" \
  || bad "wrong output (missing '$missing_line'): $OUT"
! grep -qF -e "${B#sha256:}" -e "${C#sha256:}" <<<"$(grep -v '^args' "$LOG")" \
  && ok "no request for the errored or unscanned key" || bad "B or C requested: $(cat "$LOG")"
[ "$(grep -c "^PUT .*/sbom/sha256%3A${A#sha256:}" "$LOG")" -eq 2 ] && ok "a key on two lines is stored once" || bad "A stored twice: $(cat "$LOG")"
grep -qFx "HEAD https://acct.eu.r2.example.com/sbom-bucket/sbom/sha256%3A${A#sha256:}.syft.json.zst" "$LOG" \
  && ! grep -E '^(HEAD|PUT) ' "$LOG" | grep -q 'sha256:' \
  && ok "the key's colon is %3A in every request path" || bad "path not encoded: $(grep -E '^(HEAD|PUT) ' "$LOG")"
grep -q -- "^args .*--aws-sigv4 aws:amz:auto:s3 .*-K /dev/fd/" "$LOG" \
  && [ "$(grep -c '^config ' "$LOG")" -eq "$(grep -c '^args ' "$LOG")" ] \
  && [ "$(grep '^config ' "$LOG" | sort -u)" = "config user = \"$KEY_ID:$SECRET\"" ] \
  && ok "requests signed with --aws-sigv4 aws:amz:auto:s3, the user through -K" || bad "wrong curl args: $(head -2 "$LOG")"
! grep '^args ' "$LOG" | grep -qF -e "$KEY_ID" -e "$SECRET" && ok "no credential on curl's argv" \
  || bad "credential on argv: $(grep '^args ' "$LOG" | head -1)"
[ "$(zstd -dc "$STORE/sbom/sha256%3A${A#sha256:}.syft.json.zst")" = "{\"syft\":\"sha256-${A#sha256:}\"}" ] \
  && [ "$(zstd -dc "$STORE/reports/$DATE/my-app/42-2/sha256%3A${D#sha256:}.grype.json.zst")" = '{"grype":"dir-examples-cluster-a"}' ] \
  && ok "objects are the zstd-compressed scan files" || bad "wrong object bodies: $(find "$STORE" -type f)"
M="$STORE/$RUN/manifest.json"
jq -e --arg a "$A" --arg b "$B" --arg c "$C" '
  .schema == 1 and .source == "my-app" and (.generated_at | test("^[0-9-]{10}T[0-9:]{8}Z$"))
  and .run == {repository: "example-org/my-app", workflow: "SBOM", run_id: "42", sha: "0123abc"}
  and .images == {($a): {refs: ["ghcr.io/x/a:1", "ghcr.io/x/a:2"]}, ($b): {refs: ["ghcr.io/x/b:1"]},
                  ($c): {refs: ["ghcr.io/x/c:1"]}}' "$M" >/dev/null \
  && ok "manifest v1: every image line, refs sorted and grouped, lock dir left out" || bad "wrong manifest: $(cat "$M")"
no_secret && ok "no credential in the output" || bad "credential leaked: $OUT"

# 2) HEAD 200 → present without a PUT; PUT 409 → present
rules "HEAD sha256%3A${A#sha256:}.cdx 200" "PUT sha256%3A${A#sha256:}.syft 409"
run "$LINES" put --scan-dir "$SCAN" --source my-app
[ $? -eq 0 ] && has "present sbom/$A.cdx.json.zst" && has "present sbom/$A.syft.json.zst" \
  && ! grep -q "^PUT .*${A#sha256:}.cdx" "$LOG" && ok "200 on HEAD and 409 on PUT count as present" \
  || bad "present: $OUT"

# 3) a 500 fails that object, the rest are still tried, exit 3
rules "PUT sha256%3A${A#sha256:}.syft 500" "HEAD sha256%3A${D#sha256:}.cdx 503"
run "$LINES" put --scan-dir "$SCAN" --source my-app
rc=$?
[ $rc -eq 3 ] && has "failed sbom/$A.syft.json.zst" && has "failed sbom/$D.cdx.json.zst" \
  && has "stored reports/$DATE/my-app/42-2/$D.grype.json.zst" && has "stored $RUN/manifest.json" \
  && ok "failures exit 3 after trying every object" || bad "failure: rc=$rc $OUT"
grep -qF "HTTP 500" <<<"$OUT" && no_secret && ok "the failure names the status, not the credential" || bad "failure message: $OUT"

# 4) nothing scanned (no summary.json): only the manifest, every image line still in it
mkdir -p "$TMP/empty"
rules
run "$LINES" put --scan-dir "$TMP/empty" --source my-app
[ $? -eq 0 ] && [ "$OUT" = "stored $RUN/manifest.json" ] \
  && jq -e '.images | length == 3' "$STORE/$RUN/manifest.json" >/dev/null \
  && ok "an empty scan directory still writes the manifest" || bad "empty scan dir: $OUT"

# 5) missing: prints the lines whose key lacks the syft or the CycloneDX SBOM; A has both, D only
# the syft one, B and C neither
rules "HEAD sha256%3A${A#sha256:} 200" "HEAD sha256%3A${D#sha256:}.syft 200"
run "$LINES" missing
rc=$?
[ $rc -eq 0 ] && [ "$OUT" = "$B ghcr.io/x/b:1 $SB
$C ghcr.io/x/c:1 $SC
$D - $SD" ] && ok "missing prints the lines of absent and partly stored keys" || bad "missing: rc=$rc $OUT"
[ "$(grep -c '^HEAD ' "$LOG")" -eq 6 ] && ! grep -q '^PUT ' "$LOG" \
  && [ "$(grep -c "^HEAD .*/sbom/sha256%3A${A#sha256:}\.\(syft\|cdx\)\.json\.zst$" "$LOG")" -eq 2 ] \
  && [ "$(grep -c "^HEAD .*${B#sha256:}" "$LOG")" -eq 1 ] && grep -q "^HEAD .*/sbom/sha256%3A${B#sha256:}.syft.json.zst$" "$LOG" \
  && ok "syft HEAD first, cdx HEAD only when syft is present, once per key, no PUT" || bad "missing requests: $(grep -v '^args\|^config' "$LOG")"
rules "HEAD sha256%3A${A#sha256:}.syft 200" "HEAD sha256%3A${A#sha256:}.cdx 500"
run "$A ghcr.io/x/a:1 $SA" missing
[ $? -eq 3 ] && grep -qF "sbom/$A.cdx.json.zst: HTTP 500" <<<"$OUT" && ok "missing exits 3 on an unexpected cdx status" \
  || bad "missing on cdx 500: $OUT"
rules "HEAD sha256%3A${C#sha256:} 403"
run "$LINES" missing
[ $? -eq 3 ] && grep -qF 'HTTP 403' <<<"$OUT" && no_secret && ok "missing exits 3 on an unexpected status" \
  || bad "missing on 403: $OUT"

# 6) missing environment exits 2 before any request, naming the variable only
rules
for v in R2_SBOM_ENDPOINT R2_SBOM_BUCKET R2_SBOM_ACCESS_KEY_ID R2_SBOM_SECRET_ACCESS_KEY; do
  saved=("${R2[@]}")
  mapfile -t R2 < <(printf '%s\n' "${saved[@]}" | grep -v "^$v=")
  run "$LINES" missing
  rc=$?
  R2=("${saved[@]}")
  [ $rc -eq 2 ] && [ ! -s "$LOG" ] && grep -qF "$v is not set" <<<"$OUT" && no_secret \
    && ok "missing $v exits 2" || bad "missing $v: rc=$rc $OUT"
done
GH=()
run "$LINES" put --scan-dir "$SCAN" --source my-app
[ $? -eq 2 ] && [ ! -s "$LOG" ] && ok "put without the GitHub run environment exits 2" || bad "put without GH env: $OUT"
GH=(GITHUB_REPOSITORY=example-org/my-app GITHUB_WORKFLOW=SBOM GITHUB_RUN_ID=42 GITHUB_RUN_ATTEMPT=2
  GITHUB_SHA=0123abc)

# 7) usage errors exit 2 before any request
run "$LINES";                                        [ $? -eq 2 ] && ok "no mode exits 2" || bad "no mode: $OUT"
run "$LINES" fetch;                                  [ $? -eq 2 ] && ok "unknown mode exits 2" || bad "unknown mode: $OUT"
run "$LINES" put --scan-dir "$SCAN";                 [ $? -eq 2 ] && ok "put without --source exits 2" || bad "no --source: $OUT"
run "$LINES" put --source x;                         [ $? -eq 2 ] && ok "put without --scan-dir exits 2" || bad "no --scan-dir: $OUT"
run "$LINES" put --scan-dir "$SCAN" --source a/b;    [ $? -eq 2 ] && ok "a --source with / exits 2" || bad "bad --source: $OUT"
run "$LINES" missing --extra;                        [ $? -eq 2 ] && ok "missing with arguments exits 2" || bad "missing args: $OUT"
run "notakey - $SA" missing
[ $? -eq 2 ] && [ ! -s "$LOG" ] && ok "a malformed key exits 2" || bad "malformed key: $OUT"
run "$A ghcr.io/x/a:1" missing
[ $? -eq 2 ] && ok "a line without a source exits 2" || bad "short line: $OUT"

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
