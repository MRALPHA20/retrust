# Black Hat Asia 2027 — Arsenal submission

Call for Tools closes **2 November 2026**. Everything below is paste-ready.
Figures are the ones `retrust eval` and `retrust backtest` reproduce from the
corpus; re-run both before submitting so nothing in here has drifted.

---

## Title

**ReTrust: Scoring OT Hardware for Cyber Risk Before the Purchase Order**

Alternative, if a shorter title is wanted:
**ReTrust: Procurement-Time Risk Scoring for OT Hardware**

---

## Abstract (primary — ~370 words)

Every OT security tool on the market analyses equipment you already own. Asset
inventory platforms fingerprint what is already on the wire; firmware tools like
EMBA and FACT take apart images you already have. Nobody has built the layer
above them — a defensible answer to *which of these candidate PLCs should go on
the purchase order*, at the one moment when a security decision is still cheap.

ReTrust is that layer, and building it surfaced why nobody had. Measured across
all 27,234 product entries in CISA's OT advisory corpus, exactly **26 carry a CPE
string — 0.1%**. Every conventional vulnerability tool joins products to CVEs
through CPE, which is precisely why general-purpose tooling performs so badly on
industrial gear. Manufacturer order numbers — Siemens MLFB, `6ES7518-4AX00-1AB0`
— appear on 30.1% of entries: about 315× more available, and exactly what a buyer
types onto a requisition. ReTrust keys on those instead.

The scoring is built to survive a hostile reviewer. Hard gates (CISA KEV, the FCC
Covered List, the BIS Entity List, OFAC) sit outside the weighted composite,
because a weighted disqualifier can be averaged away by good scores elsewhere.
Raw CVE counts are never scored — that would rank a diligent discloser below a
silent one. `retrust sensitivity` samples hundreds of weightings from across the
simplex and flags any verdict surviving fewer than 90% of them as a judgement
call rather than dressing it in false precision. A product that cannot be
resolved gets no score at all, since every pillar reads "no CVEs found" as good
news.

`retrust eval` recomputes every accuracy figure from your own index: **93.1%** of
26,958 version ranges decided deterministically, **99.9%** resolution precision
and recall at n=4,000. And `retrust backtest` reports a finding against the
tool's own interest — correlation with later disclosure is **+0.432**, the wrong
direction, because the score tracks disclosure maturity rather than risk. Holding
the manufacturer constant collapses it to +0.106, and to **−0.187** once the one
vendor that is half the sample is dropped. The demo walks that confounder down
live, because a scoring tool that cannot show you its own failure mode has not
earned the verdict it prints.

Python 3.10+, no third-party runtime dependencies, Apache-2.0, fully offline
against a local SQLite index.

---

## Short description (~100 words, if the form asks for one)

ReTrust scores OT hardware for cyber risk *before* you buy it, working from
public advisory data and keying on the manufacturer order number a purchase
requisition already contains. Only 26 of 27,234 product entries in CISA's OT
advisory corpus carry a CPE string — 0.1% — which is why conventional
vulnerability tooling fails on industrial equipment; order numbers are 315× more
available. Hard gates for known-exploited vulnerabilities and supply-chain
restrictions sit outside the weighted score. Accuracy (93.1% version-range
coverage, 99.9% resolution) and a back-test that reports against the tool's own
interest are both reproducible with one command.

---

## Form fields

| Field | Value |
|---|---|
| Tool name | ReTrust |
| Category (primary) | Embedded / IoT / Hardware — ICS & OT |
| Category (secondary) | Vulnerability Assessment / Supply Chain |
| Open source | Yes, Apache-2.0 |
| Source repository | **TODO — must be public before submitting** |
| Documentation | `README.md` (well past Arsenal's three-page minimum), plus `docs/build-plan.html` |
| Runtime dependencies | None beyond Python 3.10+ |
| Network required at demo time | No — runs offline against a snapshot |
| Previously presented | No |
| Session format | Arsenal station, 40 minutes |

Arsenal rules worth re-reading before you submit: a public code repository link
is mandatory, at least three pages of English documentation are required, and
paid product pitches are prohibited. ReTrust clears all three, but the repository
has to actually be published — see the checklist below.

---

## Station demo (40 minutes)

Each beat is a command that already works, so nothing has to be staged.

1. **The gap, in one table** (3 min) — `retrust eval`, whose first block is the
   CPE-versus-order-number coverage measured live off the corpus. This is the
   hook: visitors recognise immediately why their existing tooling is quiet about
   OT gear, and it is a command rather than a slide.
2. **One product** (5 min) — `retrust score --order-number 6ES7518-4AX00-1AB0
   --version 3.1.6`. A real MLFB off a real requisition, resolving to real
   advisories, with the evidence line behind every pillar.
3. **The decision** (7 min) — `retrust compare` across six candidates, one gated
   on KEV and one gated on the FCC Covered List, to the HTML report a buyer
   attaches to the purchase order.
4. **Attack the score** (8 min) — `retrust sensitivity` on a candidate whose
   verdict does *not* survive reweighting. Invite the visitor to disagree with
   the weights, then show `retrust config --init` and re-run under theirs.
5. **The back-test** (10 min) — pooled +0.432, within-vendor +0.106, −0.187
   leave-one-out. Walk the confounder down in three commands. This is the beat
   that distinguishes the tool from a scoring dashboard.
6. **The gate** (4 min) — `retrust batch bom.csv --fail-on unassessed` and its
   exit code blocking a CI job.
7. **Questions** (3 min).

Fallback: `retrust demo` runs the whole sequence end to end in one command, and
`retrust snapshot --restore` pins the exact data, so a station with no network
still gives the same numbers.

---

## Before you submit

- [ ] **Publish the repository.** It is a local git repo with 9 commits and no
      remote. Arsenal cannot accept a submission without a public code link, and
      this is the only hard blocker.
- [ ] Replace the `<you>` placeholder in the README clone URL.
- [ ] Presenter name, title, employer, bio and photo — the form wants a complete
      speaker record and reviewers read the bio.
- [ ] **Re-ingest, then re-run `retrust eval --sample 4000`.** The local index
      predates the identifier-coverage measurement, so `eval` currently abstains
      on that block. Re-cloning the CISA corpus (~134 MB) and running `ingest`
      populates it, and the 0.1% CPE figure that the abstract leads on should be
      confirmed from that output before the abstract goes in.
- [ ] Re-run `retrust backtest` and reconcile every correlation quoted above.
- [ ] Confirm the corpus snapshot date cited in reports is current.

---

## Why this should be accepted, in reviewers' terms

- **It answers a question no other tool answers.** Not a better scanner — a
  different point in the lifecycle.
- **It carries a measured research finding**, not just an implementation: CPE is
  absent from ICS advisory data, and the number is 0.1%.
- **Accuracy is a command, not a claim.** Reviewers can reproduce every figure.
- **It reports against its own interest.** The back-test result is unfavourable
  and printed anyway, with the confounder decomposed. That is rare enough in this
  category to be the thing a reviewer remembers.
- **The demo cannot half-fail.** Offline, no dependencies, one-command fallback.
