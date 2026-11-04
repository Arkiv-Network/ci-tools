#!/usr/bin/env bash
# Fixture tests for bin/check-grype-ignores: a valid ledger passes, and each kind of bad rule is
# named in the output with exit 1.
#
# Needs yq on PATH: run under `mise exec --`.
#
#   bin/tests/check-grype-ignores.test.sh   # exit 0 = all pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/../check-grype-ignores"
command -v yq >/dev/null || { echo "these tests need yq on PATH — run: mise exec -- bash $0" >&2; exit 2; }
TMP="$(mktemp -d "${SCRATCH_DIR:-/tmp}/check-grype-ignores-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
ok()  { echo "ok   - $1"; pass=$((pass + 1)); }
bad() { echo "FAIL - $1"; fail=$((fail + 1)); }

run() { OUT="$(env -i PATH="$PATH" HOME="$HOME" python3 "$SCRIPT" "$@" 2>&1)"; return $?; }
day() { date -u -d "$1" +%F; }

# 1) an empty ignore list and an empty file pass
: >"$TMP/empty.yaml"
run "$HERE/fixtures/ignore-empty.yaml" "$TMP/empty.yaml" && ok "empty ignore list and empty file pass" \
  || bad "empty ignore list should pass: $OUT"

# 2) a complete rule expiring today, and one at the 180-day limit, pass
cat >"$TMP/good.yaml" <<YAML
ignore:
  - vulnerability: CVE-2024-0001
    reason: not reachable
    expires: $(day today)
  - vulnerability: CVE-2024-0002
    package: {name: "libfoo.*"}
    reason: no fix upstream
    expires: "$(day '+180 days')"
YAML
run "$TMP/good.yaml" && ok "valid rules pass" || bad "valid rules should pass: $OUT"

# 3) the expired fixture fails and names the rule
run "$HERE/fixtures/ignore-expired.yaml"
[ $? -eq 1 ] && echo "$OUT" | grep -q 'ignore\[0\] (CVE-2021-36159): expired on 2020-01-01' \
  && ok "expired rule fails with exit 1" || bad "expired rule should fail: $OUT"

# 4) each missing or bad field is reported against its own rule
cat >"$TMP/bad.yaml" <<YAML
ignore:
  - package: {name: ".*"}
    fix-state: fixed
    reason: everything
    expires: $(day '+30 days')
  - vulnerability: CVE-2024-0003
    reason: ""
    expires: $(day '+30 days')
  - vulnerability: CVE-2024-0004
    reason: later
    expires: $(day '+181 days')
  - vulnerability: CVE-2024-0005
    reason: someday
  - vulnerability: CVE-2024-0006
    reason: typo
    expires: 2026-02-30
YAML
run "$TMP/bad.yaml"
rc=$?
[ $rc -eq 1 ] && ok "bad ledger exits 1" || bad "bad ledger should exit 1, got $rc: $OUT"
for want in 'ignore\[0\] (package name=\.\*): package name matches everything' 'ignore\[1\] (CVE-2024-0003): missing reason' \
  'ignore\[2\] (CVE-2024-0004): expires .* more than 180 days ahead' \
  'ignore\[3\] (CVE-2024-0005): expires must be YYYY-MM-DD' 'ignore\[4\] (CVE-2024-0006): .*not a valid date'; do
  echo "$OUT" | grep -q "$want" && ok "reports: $want" || bad "missing '$want' in: $OUT"
done

# 5) package-scoped rules: location or name alone, or with a vulnerability, pass
cat >"$TMP/pkg-good.yaml" <<YAML
ignore:
  - package: {location: /usr/local/bin/some-tool}
    reason: upstream binary at its newest release
    expires: $(day '+30 days')
  - package: {name: "golang.org/x/.*", type: go-module}
    reason: vendored upstream
    expires: $(day '+30 days')
  - vulnerability: CVE-2024-0008
    package: {location: "/usr/local/bin/*", version: 1.2.3}
    reason: not reachable
    expires: $(day '+30 days')
YAML
run "$TMP/pkg-good.yaml" && ok "package rules pass" || bad "package rules should pass: $OUT"

# 6) each bad package rule fails against its own rule, labelled by location, then name
cat >"$TMP/pkg-bad.yaml" <<YAML
ignore:
  - reason: neither
    expires: $(day '+30 days')
  - package: {type: go-module}
    reason: type alone
    expires: $(day '+30 days')
  - package: {locaton: /usr/local/bin/tool}
    reason: typo
    expires: $(day '+30 days')
  - package: /usr/local/bin/tool
    reason: not a mapping
    expires: $(day '+30 days')
  - package: {location: ""}
    reason: empty
    expires: $(day '+30 days')
  - package: {location: "**"}
    reason: catch-all
    expires: $(day '+30 days')
  - package: {location: /}
    reason: catch-all
    expires: $(day '+30 days')
  - package: {name: ".*"}
    reason: catch-all
    expires: $(day '+30 days')
  - package: {location: /usr/local/bin/tool}
    expires: $(day '+30 days')
  - package: {name: libfoo}
    reason: no expiry
YAML
run "$TMP/pkg-bad.yaml"
rc=$?
[ $rc -eq 1 ] && ok "bad package ledger exits 1" || bad "bad package ledger should exit 1, got $rc: $OUT"
for want in 'ignore\[0\]: missing vulnerability or package' \
  'ignore\[1\]: package needs a location or a name' \
  'ignore\[2\]: unknown package key: locaton' \
  'ignore\[3\]: package is not a mapping' \
  'ignore\[4\]: package location must be a non-empty string' \
  'ignore\[5\] (package location=\*\*): package location matches everything' \
  'ignore\[6\] (package location=/): package location matches everything' \
  'ignore\[7\] (package name=\.\*): package name matches everything' \
  'ignore\[8\] (package location=/usr/local/bin/tool): missing reason' \
  'ignore\[9\] (package name=libfoo): expires must be YYYY-MM-DD'; do
  echo "$OUT" | grep -q "$want" && ok "reports: $want" || bad "missing '$want' in: $OUT"
done
[ "$(echo "$OUT" | grep -c .)" = 10 ] && ok "one line per bad package rule" || bad "wrong line count: $OUT"

# 7) unparseable YAML and a non-list ignore fail rather than pass silently
printf 'ignore: [unclosed\n' >"$TMP/broken.yaml"
printf 'ignore: {vulnerability: CVE-2024-0007}\n' >"$TMP/notlist.yaml"
run "$TMP/broken.yaml" && bad "broken YAML should fail" \
  || { echo "$OUT" | grep -q 'cannot read' && ok "broken YAML fails" || bad "wrong message: $OUT"; }
run "$TMP/notlist.yaml" && bad "non-list ignore should fail" \
  || { echo "$OUT" | grep -q 'ignore is not a list' && ok "non-list ignore fails" || bad "wrong message: $OUT"; }

# 8) no arguments is a usage error
run
[ $? -eq 2 ] && ok "no arguments exits 2" || bad "no arguments should exit 2: $OUT"

echo "---"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
