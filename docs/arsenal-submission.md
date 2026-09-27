# Black Hat Asia 2027, Arsenal submission

Call for Tools closes **2 November 2026**. Everything below is paste-ready.
Figures are the ones `retrust eval` and `retrust backtest` reproduce from the
corpus; re-run both before submitting so nothing here has drifted.

---

## Title

**ReTrust: Scoring OT Hardware for Cyber Risk Before the Purchase Order**

Alternative, if a shorter title is wanted:
**ReTrust: Procurement-Time Risk Scoring for OT Hardware**

---

## Abstract (primary, ~390 words)

Every OT security tool on the market analyses equipment you already own. Asset
inventory platforms fingerprint what is already on the wire; firmware tools like
EMBA and FACT take apart images you already have. Nobody has built the layer
above them: a defensible answer to *which of these candidate PLCs should go on
the purchase order*, at the one moment when a security decision is still cheap.

ReTrust is that layer, and building it surfaced why nobody had. Measured across
all 27,234 product entries in CISA's OT advisory corpus, exactly **26 carry a CPE
string, 0.1%**. Every conventional vulnerability tool joins products to CVEs
through CPE, which is why general-purpose tooling performs so badly on industrial
gear. Manufacturer order numbers (Siemens MLFB, `6ES7518-4AX00-1AB0`) are
declared on 30.1% of entries, **316× more available**, rising to 35.2% once
ReTrust recovers the ones buried in product names. They are also what a buyer
types onto a requisition in the first place. ReTrust keys on those instead.

The scoring is built to survive a hostile reviewer. Hard gates (CISA KEV, the FCC
Covered List, the BIS Entity List, OFAC) sit outside the weighted composite,
because a weighted disqualifier can be averaged away by good scores elsewhere.
Raw CVE counts are never scored, since that would rank a diligent discloser below
a silent one. `retrust sensitivity` samples hundreds of weightings from across
the simplex and flags any verdict surviving fewer than 90% of them as a judgement
call instead of dressing it in false precision. A product that cannot be resolved
gets no score at all, because every pillar reads "no CVEs found" as good news.

`retrust eval` recomputes every accuracy figure from your own index: **93.1%** of
26,958 version ranges decided deterministically, **99.9%** resolution precision
and recall at n=4,000. And `retrust backtest` reports a finding against the
tool's own interest. Correlation with later disclosure is **+0.432**, the wrong
direction, because the score tracks disclosure maturity rather than risk. Holding
the manufacturer constant collapses it to +0.106, and to **−0.187** once the one
vendor that is half the sample is dropped. The demo walks that confounder down
live, because a scoring tool that cannot show you its own failure mode has not
earned the verdict it prints.

Python 3.10+, no third-party runtime dependencies, Apache-2.0, fully offline
against a local SQLite index. A clone and one command build the whole thing, so a
visitor can have it running on their own laptop, against their own bill of
materials, before they reach the next station.

---

## Short description (~110 words, if the form asks for one)

ReTrust scores OT hardware for cyber risk *before* you buy it, working from
public advisory data and keying on the manufacturer order number a purchase
requisition already contains. Only 26 of 27,234 product entries in CISA's OT
advisory corpus carry a CPE string, 0.1%, which is why conventional vulnerability
tooling fails on industrial equipment; declared order numbers are 316× more
available. Hard gates for known-exploited vulnerabilities and supply-chain
restrictions sit outside the weighted score. Accuracy (93.1% version-range
coverage, 99.9% resolution) and a back-test that reports against the tool's own
interest are both reproducible with one command. Search, vendor profiles and a
CI-friendly batch mode make it usable on a real bill of materials.

---

## Form fields

| Field | Value |
|---|---|
| Tool name | ReTrust |
| Category (primary) | Embedded / IoT / Hardware (ICS & OT) |
| Category (secondary) | Vulnerability Assessment / Supply Chain |
| Open source | Yes, Apache-2.0 |
| Source repository | **TODO: must be public before submitting** |
| Documentation | `README.md`, well past Arsenal's three-page minimum, plus `docs/build-plan.html` |
| Runtime dependencies | None beyond Python 3.10+ |
| Install | `git clone` then `python3 -m retrust.cli setup` |
| Network required at demo time | No; runs offline against a pinned snapshot |
| Previously presented | No |
| Session format | Arsenal station, 40 minutes |

Arsenal rules worth re-reading before submitting: a public code repository link
is mandatory, at least three pages of English documentation are required, and
paid product pitches are prohibited. ReTrust clears all three, but the repository
has to actually be published. See the checklist below.

---

## Station demo (40 minutes)

Every beat is a command that already works, so nothing has to be staged. Beats 2
and 3 put the visitor's own equipment on screen, which is what makes a station
memorable rather than a demo they watched.

1. **The gap, in one table** (3 min). `retrust eval`, whose first block is the
   CPE-versus-order-number coverage measured live off the corpus. This is the
   hook: visitors recognise immediately why their existing tooling is quiet about
   OT gear, and it is a command rather than a slide.
2. **Hand them the keyboard** (5 min). `retrust search <whatever they run>`.
   Almost every OT engineer who stops at the station owns a Siemens, Moxa,
   Rockwell or Schneider box, and all four are heavily represented. Search is
   what makes this possible in thirty seconds instead of needing the exact
   catalogue spelling, and a misspelling returns a shortlist rather than nothing.
3. **Their supplier** (4 min). `retrust vendor <their vendor>`: advisory history,
   remediation record, KEV hits, certificates, screening status. Point out that
   it refuses to grade the vendor, and say why.
4. **One product, with its evidence** (5 min). `retrust score --order-number
   6ES7518-4AX00-1AB0 --version 3.1.6`. A real MLFB off a real requisition,
   resolving to real advisories, with the evidence line behind every pillar.
5. **The decision** (6 min). `retrust compare` across six candidates, one gated
   on KEV and one on the FCC Covered List, to the HTML report a buyer attaches to
   the purchase order.
6. **Attack the score** (6 min). `retrust sensitivity` on a candidate whose
   verdict does *not* survive reweighting. Invite the visitor to disagree with
   the weights, then show `retrust config --init` and re-run under theirs.
7. **The back-test** (8 min). Pooled +0.432, within-vendor +0.106, −0.187
   leave-one-out. Walk the confounder down in three commands. This is the beat
   that separates the tool from a scoring dashboard.
8. **The gate** (3 min). `retrust batch bom.csv --fail-on unassessed` and its
   exit code blocking a CI job.

**Takeaway.** Two commands and they have it running: `git clone`, then
`python3 -m retrust.cli setup`. No pip, no virtualenv, no dependencies to
resolve. Worth saying out loud at the station, because "I'll try it later"
usually means never.

**Fallback.** `retrust demo` runs the whole sequence end to end in one command,
and `retrust snapshot --restore` pins the exact data, so a station with no
network still gives the same numbers. `smoke.sh` exercises all 37 command paths
if something needs checking the morning of.

---

## Before you submit

- [ ] **Publish the repository.** It is a local git repo with 17 commits and no
      remote. Arsenal cannot accept a submission without a public code link, and
      this is the only hard blocker.
- [ ] Replace the `<you>` placeholder in the README clone URL.
- [ ] Presenter name, title, employer, bio and photo. The form wants a complete
      speaker record, and reviewers read the bio.
- [x] **Every accuracy figure above re-measured from a fresh ingest**
      (3,937 advisories, 27,234 products, 2026-09-27): CPE 26 / 27,234 =
      **0.10%**, declared order numbers 8,204 = **30.12%** (316×), version-range
      coverage **93.12%**, decidable accuracy **94.71%**, round-trip precision
      and recall **99.88%** at n=4,000, order-number resolution **100%**
      (1,428/1,428).
- [x] **Back-test re-run on the same fresh index**: pooled +0.432, within-vendor
      **+0.106** (p=0.001), leave-one-out **−0.187**, 9 negative / 10 positive
      across 21 vendors and 3,814 products. Every correlation quoted above
      reproduces.
- [x] **Every command documented.** A check reads the live argument parser and
      confirms the README names every command, invents none, and shows no flag on
      a command that does not take it.
- [ ] Confirm the corpus snapshot date cited in reports is current.
- [ ] Rehearse beat 2 against a laptop with no network, using the snapshot.

---

## Why this should be accepted, in reviewers' terms

- **It answers a question no other tool answers.** Not a better scanner; a
  different point in the lifecycle.
- **It carries a measured research finding**, not just an implementation: CPE is
  absent from ICS advisory data, and the number is 0.1%.
- **Accuracy is a command, not a claim.** Reviewers can reproduce every figure on
  their own index.
- **It reports against its own interest.** The back-test result is unfavourable
  and printed anyway, with the confounder decomposed. That is rare enough in this
  category to be the thing a reviewer remembers.
- **A visitor can drive it.** Search, vendor profiles and a two-command install
  mean they look up their own equipment at the station, not a curated example.
- **The demo cannot half-fail.** Offline, no dependencies, one-command fallback,
  and a smoke script covering every command path.
