#!/usr/bin/env bash
# Exercise every command against the real index and report what broke.
#
# The test suite runs against fixtures in a temporary directory. This runs the
# shipped commands against the real 27,234-product corpus, which is where the
# differences live: a query that is fine on three fixture rows and quadratic on
# thirty thousand, an exit code that is right in-process and wrong through the
# shell, output that only misaligns once a vendor name is long enough.
#
# Usage:  ./smoke.sh          expects an index at data/retrust.db

set -u
RETRUST="python3 -m retrust.cli"
pass=0; fail=0; failed=()

# check <expected-exit> <description> -- <command...>
check() {
  local want="$1" what="$2"; shift 3
  local out; out=$("$@" 2>&1); local got=$?
  if [ "$got" -ne "$want" ]; then
    printf '  FAIL  %-52s exit %s, wanted %s\n' "$what" "$got" "$want"
    printf '        %s\n' "$(echo "$out" | head -3)"
    fail=$((fail + 1)); failed+=("$what")
  else
    printf '  ok    %-52s\n' "$what"
    pass=$((pass + 1))
  fi
}

# contains <substring> <description> -- <command...>
#
# Output is wrapped to the terminal, so a phrase that spans a line break would
# never match. Whitespace is collapsed to one line before looking.
contains() {
  local want="$1" what="$2"; shift 3
  local out; out=$("$@" 2>&1 | tr -s '[:space:]' ' ')
  if echo "$out" | grep -qF -- "$want"; then
    printf '  ok    %-52s\n' "$what"
    pass=$((pass + 1))
  else
    printf '  FAIL  %-52s missing %q\n' "$what" "$want"
    printf '        %s\n' "$(echo "$out" | head -3)"
    fail=$((fail + 1)); failed+=("$what")
  fi
}

echo "== the index =="
check 0 "bare retrust greets"                     -- $RETRUST
check 0 "stats"                                   -- $RETRUST stats
contains "28,951" "stats counts the whole corpus" -- $RETRUST stats

echo
echo "== interactive shell =="
printf 'q\n' | $RETRUST shell >/dev/null 2>&1 \
  && { echo "  ok    the menu opens and quits"; pass=$((pass+1)); } \
  || { echo "  FAIL  the menu opens and quits"; fail=$((fail+1)); failed+=("shell quit"); }
printf '4\nMoxa\nq\n' | $RETRUST shell 2>&1 | grep -q "VENDOR DOSSIER" \
  && { echo "  ok    a menu choice runs its action"; pass=$((pass+1)); } \
  || { echo "  FAIL  a menu choice runs its action"; fail=$((fail+1)); failed+=("shell action"); }
printf '4\nMoxa\nq\n' | $RETRUST shell 2>&1 | grep -q 'retrust vendor Moxa' \
  && { echo "  ok    it prints the equivalent command"; pass=$((pass+1)); } \
  || { echo "  FAIL  it prints the equivalent command"; fail=$((fail+1)); failed+=("shell echo"); }
printf '9\nq\n' | $RETRUST shell 2>&1 | grep -q "not on the menu" \
  && { echo "  ok    a wrong choice does not end it"; pass=$((pass+1)); } \
  || { echo "  FAIL  a wrong choice does not end it"; fail=$((fail+1)); failed+=("shell bad choice"); }

echo
echo "== search =="
check 0 "product search finds a known PLC"        -- $RETRUST search S7-1500
check 0 "vendor search"                           -- $RETRUST search --vendors siemens
check 0 "order-number search"                     -- $RETRUST search --order-number 6ES7518
check 1 "a search with no hits exits 1"           -- $RETRUST search zzzznotathing
check 0 "scoped to one vendor"                    -- $RETRUST search --vendor Moxa EDS
contains "6ES7518-4AX00-1AB0" "order numbers print as the vendor wrote them" \
  -- $RETRUST search --order-number 6ES7518
# A bare punctuation query normalises to nothing; it must not match everything.
check 1 "punctuation-only query matches nothing"  -- $RETRUST search -- -
check 1 "LIKE wildcards are not wildcards"        -- $RETRUST search '%'

echo
echo "== vendor dossier =="
check 0 "a known manufacturer"                    -- $RETRUST vendor Moxa
check 1 "an unknown one exits 1"                  -- $RETRUST vendor Nobodyatall
contains "similar name" "a typo gets a shortlist" -- $RETRUST vendor Siemems
contains "not a verdict" "counts are not a grade" -- $RETRUST vendor Siemens
contains "covered list" "screening shows on the dossier" -- $RETRUST vendor Hikvision
check 1 "punctuation-only name is not a vendor"   -- $RETRUST vendor -- -

echo
echo "== scoring =="
check 0 "score by order number"                   -- $RETRUST score --order-number 6ES7518-4AX00-1AB0 --version 3.1.6
check 0 "score by vendor and product"             -- $RETRUST score --vendor ABB --product "AC 800M"
check 2 "an unknown product is NOT ASSESSED"      -- $RETRUST score --vendor Nobody --product Nothing
contains "Known exploited" "KEV forces AVOID"     -- $RETRUST score --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6
contains "covered list" "a listed vendor is gated" -- $RETRUST score --vendor Hikvision --product "IP Camera"

echo
echo "== comparing and batching =="
check 0 "compare ranks candidates"                -- $RETRUST compare --candidate "ABB|AC 800M" --candidate "Moxa|EDS-405A" --no-sensitivity
check 1 "batch exits 1 on a disqualified part"    -- $RETRUST batch examples/candidates.csv --no-sensitivity
check 0 "batch exits 0 on a clean list"           -- $RETRUST batch examples/approved-bom.csv --no-sensitivity --fail-on never

echo
echo "== lev =="
contains "NIST CSWP 41" "the method is attributed"  -- $RETRUST lev --vendor "Schneider Electric" --product "Modicon M340"
contains "augments KEV" "augment-not-replace is stated" -- $RETRUST lev --vendor "Schneider Electric" --product "Modicon M340"
contains "expectation over the set" "the expected count is labelled" \
  -- $RETRUST lev --vendor "Schneider Electric" --product "Modicon M340"
check 2 "an unresolvable product cannot be estimated" -- $RETRUST lev --vendor Nobody --product Nothing
check 0 "one CVE by name"                           -- $RETRUST lev --cve CVE-2015-7937
check 0 "the audit prints corpus base rates"        -- $RETRUST lev --audit
contains "Across the whole corpus" "a count is compared, not just reported" \
  -- $RETRUST lev --vendor "Schneider Electric" --product "Modicon M340"
contains "rises with exposure" "the age confound is surfaced" -- $RETRUST lev --audit

echo
echo "== ssvc =="
SSVC="--exposure controlled --automatable yes --human-impact high"
check 1 "a KEV finding demands out-of-cycle work"  -- $RETRUST ssvc --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6 $SSVC
contains "Carnegie Mellon" "the table is attributed" -- $RETRUST ssvc --vendor ABB --product "AC 800M" $SSVC
contains "describe your plant" "the context is the buyer's" -- $RETRUST ssvc --vendor ABB --product "AC 800M" $SSVC
contains "understates" "the exploitation limit is stated" -- $RETRUST ssvc --vendor ABB --product "AC 800M" $SSVC
check 2 "an unresolvable product cannot be placed"  -- $RETRUST ssvc --vendor Nobody --product Nothing $SSVC
check 2 "a missing context flag is refused"         -- $RETRUST ssvc --vendor ABB --product "AC 800M" --exposure open
check 2 "an invalid context value is refused"       -- $RETRUST ssvc --vendor ABB --product "AC 800M" --exposure everywhere --automatable yes --human-impact high

echo
echo "== alternatives =="
check 0 "a gated product gets suggestions"         -- $RETRUST alternatives --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6
contains "not a recommendation" "the caveat is printed" -- $RETRUST alternatives --vendor Siemens --product "SIMATIC S7-1500"
contains "family member(s)" "skipped ones are counted, not hidden" \
  -- $RETRUST alternatives --vendor Siemens --product "SIMATIC S7-1500"
contains "equal terms" "a version is flagged as unequal" -- $RETRUST alternatives --vendor Siemens --product "SIMATIC S7-1500" --version 3.1.6
check 1 "a product with no family exits 1"         -- $RETRUST alternatives --vendor Moxa --product EDS-405A
check 1 "an unresolvable product exits 1"          -- $RETRUST alternatives --vendor Nobody --product Nothing

echo
echo "== diff: what changed since a stored run =="
$RETRUST batch examples/candidates.csv --json /tmp/retrust-smoke-before.json \
  --no-sensitivity >/dev/null 2>&1
check 0 "an unchanged index reports no change"     -- $RETRUST diff /tmp/retrust-smoke-before.json
contains "unchanged" "it says how many held still" -- $RETRUST diff /tmp/retrust-smoke-before.json
# Rewrite one verdict to stand for what January looked like, then diff.
python3 - <<'EDIT'
import json
path = "/tmp/retrust-smoke-before.json"
d = json.load(open(path))
for r in d["results"]:
    if "Hikvision" in r["product"]:
        r.update(verdict="PREFER", score=88.0, gates=[])
json.dump(d, open(path, "w"))
EDIT
check 1 "a newly gated product exits 1"            -- $RETRUST diff /tmp/retrust-smoke-before.json
contains "NEWLY GATED" "and is called out as gated" -- $RETRUST diff /tmp/retrust-smoke-before.json
check 1 "a result with no queries is refused"      -- $RETRUST diff examples/candidates.csv

echo
echo "== machine-readable output =="
$RETRUST score --vendor ABB --product "AC 800M" --json - --no-sensitivity 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['results'][0]['verdict']" \
  && { echo "  ok    score --json parses"; pass=$((pass+1)); } \
  || { echo "  FAIL  score --json parses"; fail=$((fail+1)); failed+=("score --json"); }
$RETRUST compare --candidate "ABB|AC 800M" --json - --no-sensitivity 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['candidates']==1" \
  && { echo "  ok    compare --json parses"; pass=$((pass+1)); } \
  || { echo "  FAIL  compare --json parses"; fail=$((fail+1)); failed+=("compare --json"); }

echo
echo "== analysis =="
check 0 "eval reproduces the accuracy figures"    -- $RETRUST eval --sample 200
check 0 "sensitivity"                             -- $RETRUST sensitivity --vendor Moxa --product EDS-405A --samples 50
check 0 "backtest"                                -- $RETRUST backtest --permutations 50
check 0 "config prints the weights"               -- $RETRUST config

echo
echo "== shell integration =="
check 0 "bash completion"                         -- $RETRUST completion bash
check 0 "zsh completion"                          -- $RETRUST completion zsh
check 2 "an unknown shell is refused"             -- $RETRUST completion fish
$RETRUST completion bash | bash -n \
  && { echo "  ok    bash completion is valid bash"; pass=$((pass+1)); } \
  || { echo "  FAIL  bash completion is valid bash"; fail=$((fail+1)); failed+=("bash -n"); }

echo
echo "== integrity =="
check 0 "digests verify"                            -- $RETRUST verify --limit 40 --no-signatures
contains "same clone" "a digest is not an origin proof" -- $RETRUST verify --limit 10 --no-signatures
contains "signed by:" "the signer fingerprint is reported" -- $RETRUST verify --limit 10
# With the key imported these verify; without it the report says how to get it.
# Either way the signer question must be answered, never silently skipped.
contains "ORIGIN" "origin is reported separately from content" \
  -- $RETRUST verify --limit 10
check 1 "a missing corpus is reported"              -- $RETRUST verify --csaf /nonexistent

echo
echo "== misuse =="
check 2 "an unknown command is rejected"          -- $RETRUST frobnicate
check 1 "a missing index is reported, not crashed" -- $RETRUST --db /nonexistent/x.db stats

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || { printf 'failed: %s\n' "${failed[*]}"; exit 1; }
