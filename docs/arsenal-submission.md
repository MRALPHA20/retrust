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

## Abstract (primary, 500 words)

Every OT security tool analyses equipment you already own. Asset inventory
platforms fingerprint what is on the wire; firmware tools take apart images you
already have. Nobody has built the layer above them: a defensible answer to
*which of these candidate PLCs should go on the purchase order*, at the one
moment a security decision is still cheap.

ReTrust is that layer, and building it surfaced why nobody had. Measured across
all 27,234 product entries in CISA's OT advisory corpus, exactly **26 carry a CPE
string, 0.1%**. Every conventional vulnerability tool joins products to CVEs
through CPE, which is why general-purpose tooling performs so badly on industrial
gear. Manufacturer order numbers (Siemens MLFB, `6ES7518-4AX00-1AB0`) are
declared on 30.1% of entries, **316× more available**, and are what a buyer types
onto a requisition anyway. ReTrust keys on those instead.

The scoring is built to survive a hostile reviewer. Hard gates (CISA KEV, the FCC
Covered List, the BIS Entity List, OFAC) sit outside the weighted composite,
because a weighted disqualifier can be averaged away by good scores elsewhere.
Raw CVE counts are never scored, since that would rank a diligent discloser below
a silent one. A product that cannot be resolved gets no score at all, because
every pillar reads "no CVEs found" as good news. And `retrust sensitivity` flags
a verdict surviving fewer than 90% of random weightings as a judgement call.

`retrust eval` recomputes every accuracy figure from your own index: **93.1%** of
26,958 version ranges decided deterministically, **99.9%** resolution precision
and recall at n=4,000. And `retrust backtest` reports against the tool's own
interest. Correlation with later disclosure is **+0.438**, the wrong direction,
because the score tracks disclosure maturity rather than risk. Holding the
manufacturer constant collapses it to +0.159, and to **+0.001** once the vendor
that is half the sample is dropped: nothing at all. The demo walks that
confounder down live, because a scoring tool that cannot show its own failure
mode has not earned the verdict it prints.

Two published standards are implemented on top of that, and made to disagree in
public. `retrust ssvc` places every finding on CERT/CC's SSVC deployer tree,
reproduced from their repository rather than rewritten, with three of its four
decision points left for the buyer because they describe a plant this tool never
sees. `retrust lev` implements NIST CSWP 41. On Delta Electronics DIAEnergie,
SSVC returns 72 findings all marked *scheduled* because none are in KEV, while
LEV estimates **23 of those same 72 have probably already been exploited**. The
tool prints both, and `retrust lev --audit` measures whether LEV discriminates
before anyone leans on it.

Building it turned up a second measured finding. CISA signs all 3,937 OT
advisories with one PGP key, and `retrust verify` reports a fingerprint we could
not obtain from any major keyserver, the repository, or CISA's CSAF
provider-metadata URL. If that holds, those signatures cannot today be verified
by anyone downstream.

The interface follows ISA-101, the HMI standard for industrial control rooms, and
a menu sits beside the flags. Python 3.10+, no dependencies, Apache-2.0, offline:
a clone and one command builds it.

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
interest are both reproducible with one command. It also implements CERT/CC's
SSVC deployer tree and NIST CSWP 41 (Likely Exploited Vulnerabilities), and shows
where the two disagree: one real product returns 72 findings SSVC calls
"scheduled" while LEV estimates 23 of them have probably been exploited already.
Search, vendor profiles, bill-of-materials scoring and a CI exit code make it
usable on a real purchase order.

---

## Form fields

| Field | Value |
|---|---|
| Tool name | ReTrust |
| Category (primary) | Embedded / IoT / Hardware (ICS & OT) |
| Category (secondary) | Vulnerability Assessment / Supply Chain |
| Open source | Yes, Apache-2.0 |
| Source repository | **TODO: must be public before submitting** |
| Documentation | `docs/ReTrust-Guide.pdf`, an 11-page printable user guide, plus a long `README.md` and `docs/build-plan.html`. Arsenal's minimum is three pages |
| Runtime dependencies | None beyond Python 3.10+ |
| Install | `git clone` then `python3 -m retrust.cli setup` |
| Network required at demo time | No; runs offline against a pinned snapshot |
| Previously presented | No |
| Session format | Arsenal station, 40 minutes |
| Screenshots | `docs/screenshots/comparison-light.png` and `-dark.png`, regenerated by `make docs` so they cannot drift from the code |

Arsenal rules worth re-reading before submitting: a public code repository link
is mandatory, at least three pages of English documentation are required, and
paid product pitches are prohibited. ReTrust clears all three, but the repository
has to actually be published. See the checklist below.

---

## Station demo (40 minutes)

Every beat is a command that already works, so nothing has to be staged. Beats 2
and 3 put the visitor's own equipment on screen, which is what makes a station
memorable rather than a demo they watched.

1. **The gap, in one table** (2 min). `retrust eval`, whose first block is the
   CPE-versus-order-number coverage measured live off the corpus. This is the
   hook: visitors recognise immediately why their existing tooling is quiet about
   OT gear, and it is a command rather than a slide.
2. **Hand them the keyboard** (5 min). `retrust shell` if they would rather be
   asked than type flags, otherwise `retrust search <whatever they run>`.
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
6. **Attack the score** (5 min). `retrust sensitivity` on a candidate whose
   verdict does *not* survive reweighting. Invite the visitor to disagree with
   the weights, then show `retrust config --init` and re-run under theirs.
7. **Two standards disagreeing** (7 min). On one product, `retrust ssvc` returns
   72 findings all marked *scheduled*, because nothing is in KEV; `retrust lev`
   estimates 23 of the same 72 have probably been exploited already. Then
   `retrust lev --audit` shows why the second number is credible (KEV median LEV
   1.000 against 0.162) and where it is weak (2.6% of young CVEs clear the
   threshold against 87.5% of old ones). This is the strongest beat in the set:
   two published methods, one corpus, an honest account of the gap.
8. **The back-test** (6 min). Pooled +0.438, within-vendor +0.159, +0.001
   leave-one-out. Walk the confounder down in three commands: hold the vendor
   constant and most of it goes, drop the vendor that is half the sample and
   nothing measurable is left.
9. **The gate, and where the data came from** (2 min). `retrust batch bom.csv
   --fail-on unassessed` and its exit code blocking a CI job, then
   `retrust verify`: 3,937 digests checked, one signer, and a key nobody can
   fetch. A good note to end on, because it is the question every visitor should
   be asking of any tool that scores from someone else's feed.

**Takeaway.** Two commands and they have it running: `git clone`, then
`python3 -m retrust.cli setup`. No pip, no virtualenv, no dependencies to
resolve. Worth saying out loud at the station, because "I'll try it later"
usually means never.

Print `docs/ReTrust-Guide.pdf` to hand out. Its first page is a quick start that
takes somebody from a clone to a scored comparison in three steps, so a visitor
who runs out of time at the station still leaves able to use the tool. The rest
covers the pipeline, both ways of driving it, and how to read a verdict.

**Fallback.** `retrust demo` runs the whole sequence end to end in one command,
and `retrust snapshot --restore` pins the exact data, so a station with no
network still gives the same numbers. The snapshot is **7.3 MB** and already
carries the LEV estimates and the EPSS history they were built from, so beat 7
works offline without re-fetching anything. `smoke.sh` exercises all 67 command
paths if something needs checking the morning of.

---

## The look, and why it is that look

Arsenal reviewers see screenshots before they see a demo, so this is worth being
explicit about. ReTrust does not borrow a security-tool aesthetic. Its interface
is built on **ISA-101**, the HMI design standard for industrial control rooms,
which is the same standard the people buying this equipment already work in front
of all day.

The rules that follow from it are not decoration, and each one does a job:

| Rule | What it buys |
|---|---|
| Low-chroma grey field, never pure white or black | ISA-101 rejects both. A control room where everything is colourful is one where nothing stands out |
| Colour only on a verdict, a gate or a meter fill | Four state colours exist. Headings, borders and links never take one, so an AVOID is visible from across a room |
| Identifiers set in monospace | An order number is a part number stamped on a nameplate. `6ES7518-4AX00-1AB0` should read like one |
| Uppercase letter-spaced panel labels | The engraved legends on control gear |
| A verdict-coloured stripe down each product block | The panel indicator lamp, and how a reader skims a six-candidate report |
| Hairline rules, no shadows or gradients | A mimic diagram, not a dashboard |

Both surfaces are built on the same system, so the terminal and the PDF a buyer
attaches to a purchase order read as one product. The terminal draws its
structure from box characters rather than colour, so `NO_COLOR`, a pipe and a
projector that eats contrast all still show a deliberate layout. The report
carries no script, no external asset and no web font, so it opens offline years
later and survives being emailed.

The reason this matters for the submission rather than being a vanity item: the
tool argues that OT procurement is a distinct problem that general-purpose
security tooling handles badly. An interface borrowed from general-purpose
security tooling would undercut that on sight.

---

## A second finding: the advisories cannot be verified downstream

Worth flagging separately, because it is a finding about the ecosystem rather
than about the tool, and a reviewer may know something we do not.

CISA ships a SHA-512 and a detached PGP signature beside every advisory in its
CSAF repository. `retrust verify` checks both and keeps them apart, because they
answer different questions: a digest and the file it describes came from the same
clone, so it catches corruption after download but not a substituted repository.
Only the signature survives a hostile mirror.

Sampling the corpus, **one key signed all 3,937 advisories**, fingerprint
`144A ED0A 57BE 7D4A E835 D9D8 CAC5 AC4F 7416 4B17`. That consistency is itself
a useful property; a subset signed by a second key is what a partially
substituted mirror would look like, and the tool flags it.

The problem is obtaining that key. We could not find it in:

| Where we looked | Result |
|---|---|
| `keys.openpgp.org`, `keyserver.ubuntu.com`, `pgp.mit.edu` | no data for the fingerprint |
| `cisagov/CSAF` repository root and `csaf_files/` | 404 |
| `https://www.cisa.gov/.well-known/csaf/provider-metadata.json` | 404 |
| The cloned corpus itself | no standalone key, no provider metadata |

If that is right, the signatures on the authoritative OT advisory feed cannot be
verified by any third party, and a downstream consumer has integrity against
their own copy but no assurance of origin at all. **We would genuinely like to be
wrong about this**, which is part of why it is in the submission: an Arsenal
audience is the right room to ask.

What the tool does about it is the honest minimum. `--fetch-key` asks a keyserver
for exactly the fingerprint the signatures name and discards anything else, so
the keyserver never gets to choose the key. `--key FILE` accepts one obtained out
of band, which is the only route that works today. And the report never presents
the corpus naming its own signer as evidence of origin, because it is not: it
tells you to confirm that fingerprint elsewhere.

---

## Before you submit

- [ ] **Publish the repository.** It is a local git repo with 26 commits and no
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
- [x] **Back-test re-run after the scoring change**: pooled +0.438,
      within-vendor **+0.159** (p=0.001), leave-one-out **+0.001**, 8 negative /
      12 positive across 21 vendors and 3,814 products. Every correlation quoted
      above reproduces.
- [x] **Every command documented.** A check reads the live argument parser and
      confirms the README names every command, invents none, and shows no flag on
      a command that does not take it.
- [x] **Documentation clears the three-page minimum several times over.** An
      11-page printable guide (`docs/ReTrust-Guide.pdf`), a README covering every
      command, and the build plan. The guide is printed from `docs/user-guide.html`
      by `make guide`, so it is rebuilt from source rather than hand-maintained
      and cannot drift from the figures it quotes.
- [ ] Print 30 to 50 copies of the guide for the station.
- [ ] Confirm the corpus snapshot date cited in reports is current.
- [x] **LEV checked before being relied on.** `retrust lev --audit` over all
      12,003 corpus CVEs with EPSS history: median LEV 1.000 for KEV-listed
      against 0.162 for the rest (6× separation, NIST's own validation), and the
      age confound measured at 2.6% / 12.6% / 87.5% clearing the threshold by
      band. Per-product counts print against that base rate.
- [ ] Rehearse beats 2 and 7 on a laptop with no network, from the snapshot
      alone. Beat 2 takes a visitor's arbitrary query and beat 7 needs the LEV
      tables, so these are the two that can fail in a way the others cannot.
- [ ] Run `retrust lev --update` on the demo machine, or restore the snapshot,
      well before the session. The fetch is 67 files and about four minutes.

---

## Why this should be accepted, in reviewers' terms

- **It answers a question no other tool answers.** Not a better scanner; a
  different point in the lifecycle.
- **It carries two measured research findings**, not just an implementation.
  CPE is absent from ICS advisory data, and the number is 0.1%. And CISA signs
  every OT advisory with a key we could not obtain from any public keyserver,
  the repository, or its CSAF provider metadata, which would mean those
  signatures are unverifiable downstream.
- **Accuracy is a command, not a claim.** Reviewers can reproduce every figure on
  their own index.
- **It reports against its own interest.** The back-test result is unfavourable
  and printed anyway, with the confounder decomposed. That is rare enough in this
  category to be the thing a reviewer remembers.
- **A visitor can drive it.** Search, vendor profiles and a two-command install
  mean they look up their own equipment at the station, not a curated example.
- **It implements two standards and audits one of them.** CERT/CC's SSVC tree is
  reproduced from source with a test checking all 72 rows; NIST CSWP 41 is
  implemented and then measured to see whether its threshold discriminates on OT
  data at all. The answer is printed either way.
- **The demo cannot half-fail.** Offline, no dependencies, one-command fallback,
  and a smoke script covering every command path.
- **It has a visual identity of its own**, derived from the standard its own
  users work in front of rather than borrowed from another tool. Screenshots
  read as an instrument, which is what a station wants, and the printed guide is
  set in the same language so the handout looks like the product.
- **A visitor can leave able to use it.** The guide opens on a three-step quick
  start, so somebody who only gets four minutes at the station still walks away
  with something they can run.
