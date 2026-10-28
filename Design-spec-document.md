# ReTrust — Control Room Design Language

Version 1.0 · Theme A "Control Room" · for the RT8 assessment application

A dark, dense, operator-console interface for engineers and procurement reviewers who assess OT hardware (PLCs, switches, controllers) against public security advisories. It borrows the look of SCADA/HMI and monitoring tools so the audience reads it as familiar: numbers in monospace, status carried by shape and word, and color used sparingly.

---

## 1. Principles

1. **Evidence over decoration.** Every pixel either shows an input, a calculation, or a source. The RT8 inputs (T, I, A, H, U) are shown, never hidden behind a single number.
2. **Verdict first, proof one glance away.** The verdict and score sit top-left of every result. The reasons sit directly beside and below them.
3. **Unknown is a first-class state.** Missing material evidence is VERIFY, not a lower score. Gaps are drawn dashed and violet everywhere (fields, cards, bars, badges) so "we don't know" never looks like "it's fine".
4. **Color is reserved.** Cyan means "you can act on this". Teal / amber / coral / violet mean verdict or fix status only. Nothing else on screen is allowed those hues.
5. **Never color alone.** Every status has a glyph and a word. The UI must remain readable in grayscale.
6. **Numbers are aligned and monospaced.** Scores, CVSS, EPSS, versions, order numbers and CVE IDs always use the mono face with tabular figures.

---

## 2. Design tokens

### 2.1 Color

| Token | Hex | Use |
|---|---|---|
| `--ground` | `#0B0E13` | Page background |
| `--bar` | `#0F131A` | Header, inset strips (blocker-free notice, code wells) |
| `--surface` | `#131821` | Cards, panels, inputs |
| `--raised` | `#1E2633` | Selected segment, hover row, track backgrounds |
| `--rule` | `#263042` | Hairline dividers, card borders (decorative) |
| `--rule-row` | `#1E2633` | Table row separators |
| `--control-border` | `#6F7F99` | Borders of interactive controls (inputs, outline buttons, checkboxes). ≥ 3:1 required for UI components |
| `--text` | `#E6EAF0` | Primary text |
| `--text-2` | `#C5CCD8` | Secondary body text inside alerts |
| `--muted` | `#8B96A8` | Labels, meta, captions |
| `--action` | `#5CCBEE` | Links, primary button fill, focus ring, active nav underline, IDs |
| `--action-hover` | `#9BE0F5` | Link / ghost-button hover |
| `--on-action` | `#06121A` | Text on cyan fills |
| `--prefer` | `#2FBFA0` | PREFER verdict, "fixed" status, OK ticks |
| `--conditional` | `#F0A53A` | CONDITIONAL verdict, "fix available, not applied" |
| `--avoid` | `#FF6B5E` | AVOID verdict, blockers, "no fix / mitigation only", KEV |
| `--verify` | `#A78BFA` | VERIFY verdict, evidence gaps, neutral-substituted pillars |
| `--on-avoid` | `#1A0604` | Text on solid coral (KEV chip, blocker tag) |

Tinted fills for verdict surfaces use the verdict hue at **14%** alpha with a **50%** alpha 1px border. Verdict-colored track segments in band bars use **35%** alpha.

**Contrast (calculated, WCAG relative luminance):** `--text` 14.7:1 on surface; `--muted` 6.0:1 on surface and 5.1:1 on raised; `--action` 9.5:1; teal 7.7; amber 8.6; coral 6.4; violet 6.5 (all on `--surface`). Cyan button label `--on-action` on `--action` 10.1:1; `--on-avoid` on coral 7.0:1. All text passes 4.5:1.
`--rule` against surface is 1.3:1 and is therefore **decorative only**. Never use it as the sole boundary of an interactive control, use `--control-border`.

> Note: the exploration artboards used `#36435A` for control borders (1.8:1). The production token is `--control-border: #6F7F99` (4.4:1 on surface) to meet the 3:1 non-text requirement.

### 2.2 Typography

| Role | Family | Weight | Size / line | Notes |
|---|---|---|---|---|
| Score hero | IBM Plex Mono | 500 | 72 / 1 | Tabular figures. 56 on cards ≤ 480 px |
| Page title | IBM Plex Sans | 600 | 26 / 1.25 | Product name |
| Section title | IBM Plex Sans | 600 | 18 / 1.3 | Modal and drawer titles |
| Body | IBM Plex Sans | 400 | 14 / 1.45 | Default |
| Body strong | IBM Plex Sans | 600 | 14 / 1.45 | Blocker headline |
| Label | IBM Plex Sans | 400 | 12 / 1.4 | Form labels, `--muted` |
| Panel label | IBM Plex Mono | 500 | 12 / 1.3 | UPPERCASE, letter-spacing 0.06em, `--muted` |
| Mono data | IBM Plex Mono | 400 | 13 / 1.4 | IDs, versions, table numerics |
| Mono small | IBM Plex Mono | 400 | 11–12 / 1.3 | Chips, axis labels, weights |
| Verdict tag | IBM Plex Mono | 600 | 12 / 1 | UPPERCASE, letter-spacing 0.08em |
| Button | IBM Plex Sans | 600 (primary), 500 (other) | 13–14 | |

Fonts load from Google Fonts: `IBM Plex Sans` (400/500/600/700) and `IBM Plex Mono` (400/500/600). Fallbacks: `system-ui, sans-serif` and `ui-monospace, Menlo, monospace`. Use `font-variant-numeric: tabular-nums` on all numeric columns. Mixed-case only for prose; UPPERCASE is limited to panel labels and verdict tags.

### 2.3 Spacing, radius, borders, elevation

- **Spacing scale (px):** 2, 4, 6, 8, 10, 12, 16, 20, 24, 32, 48. Card padding 20. Table cell padding 10–12 × 8–20. Page gutter 24. Gap between cards 20.
- **Radius:** `--r-sm: 2px` (chips, KEV tag), `--r-md: 3px` (badges, segments), `--r-lg: 4px` (buttons, inputs, alerts, inset strips), `--r-card: 6px` (cards). Nothing above 6px; no pills.
- **Borders:** 1px `--rule` on cards; row separators 1px `--rule-row`.
- **Elevation:** None. Depth comes from the surface ladder `ground → bar/surface → raised`. Only overlays (menus, modals) get a shadow: `0 8px 24px rgba(0,0,0,.5)` plus a 1px `--control-border`-colored edge.
- **Max content width:** 1360 px centered. Tables scroll horizontally inside their card; the page never scrolls sideways.

### 2.4 Iconography

1.5–2px stroke, square-ish line icons, 16 px in dense rows and 22 px for the logo. Colored only when the icon is a verdict or status glyph. Verdict glyphs are text characters in the mono face so they align with the label:

| Verdict | Glyph | Word |
|---|---|---|
| Prefer | `●` | PREFER |
| Conditional | `◆` | CONDITIONAL |
| Avoid | `■` | AVOID |
| Verify | `?` | VERIFY + range |
| OK / no blockers | `✓` (teal) | |

### 2.5 Motion

Functional only. 120 ms ease-out for hover, press and focus; 200 ms for the score bar marker and pillar bars when a result loads (width/left transition from 0). Skeleton shimmer is replaced by a static pulsing `--raised` block (1.2 s, opacity .6↔1). Respect `prefers-reduced-motion: reduce`: no transitions, no pulse.

### 2.6 CSS custom properties (drop-in)

```css
:root {
  --ground:#0B0E13; --bar:#0F131A; --surface:#131821; --raised:#1E2633;
  --rule:#263042; --rule-row:#1E2633; --control-border:#6F7F99;
  --text:#E6EAF0; --text-2:#C5CCD8; --muted:#8B96A8;
  --action:#5CCBEE; --action-hover:#9BE0F5; --on-action:#06121A;
  --prefer:#2FBFA0; --conditional:#F0A53A; --avoid:#FF6B5E; --verify:#A78BFA; --on-avoid:#1A0604;
  --font-sans:'IBM Plex Sans',system-ui,sans-serif;
  --font-mono:'IBM Plex Mono',ui-monospace,Menlo,monospace;
  --r-sm:2px; --r-md:3px; --r-lg:4px; --r-card:6px;
}
body { background:var(--ground); color:var(--text); font:400 14px/1.45 var(--font-sans); }
.num { font-family:var(--font-mono); font-variant-numeric:tabular-nums; }
:focus-visible { outline:2px solid var(--action); outline-offset:2px; }
```

---

## 3. Layout

- **App shell:** sticky-less top header (no sidebar). Header → page content (max 1360). Footer carries the standing disclaimer.
- **Result page grid:** `repeat(auto-fit, minmax(380px, 1fr))`, gap 20. The score card takes 1 column; the exposure card spans 2. Below, the evidence table spans full width.
- **Breakpoints:** ≥ 1100 two-up result layout. 640–1099 single column, cards stack in the order *Score → Exposure → Evidence*. < 640 header wraps, nav becomes a horizontally scrollable row, action buttons wrap to full-width rows, tables scroll in their card (`min-width` 620–860 px). Touch targets ≥ 44 px height on primary controls; dense 32 px segment buttons stay ≥ 44 px on touch devices via padding.
- **Reading order on a result:** identity → actions → verdict+score → blockers → pillars → exposure units → gaps → evidence → disclaimer.

---

## 4. Components — how each looks in ReTrust

Each entry gives: **where it appears · anatomy · states · rules.**

### 4.1 App header

- **Where:** top of every page. Background `--bar`, bottom border 1px `--rule`, padding 12×24.
- **Anatomy (left→right):** shield-check logo (22 px, `--action` stroke) · wordmark "ReTrust" (Sans 700 / 16, letter-spacing .02em) · model tag `RT8` (Mono 11, `--muted`, 1px `--rule` border, radius 3, padding 1×6) · primary nav · global search · snapshot status.
- **Snapshot status:** 8 px dot + Mono 12 `--muted` text, e.g. `● Snapshot · offline · 2026-10-28`. Dot is `--prefer` when the data snapshot is current, `--conditional` when stale, `--avoid` when missing.
- **Wraps** at narrow widths; search keeps `flex: 1 1 260px`.

### 4.2 Primary navigation

- Items: Assess · Compare · Search · Methodology. Sans 14, padding 10×12.
- **Default** `--muted`. **Hover** `--text`. **Active** `--text` with a 2px `--action` bottom border. **Focus** standard 2px cyan ring.
- No icons, no badges. A count (Mono 11, raised chip) may follow *Compare* when a shortlist exists.

### 4.3 Global search

- 36 px high, max-width 360, Mono 13, `--surface` fill, 1px `--control-border`, radius 4. Placeholder `Order no. or vendor / model  ⌘K` in `--muted`.
- **Focus:** border `--action`, no glow. **Results popover:** `--surface`, 1px control-border, overlay shadow, rows 40 px: order number (Mono, `--action`), product name (Sans), vendor (Mono 12 `--muted`, right aligned). Keyboard: ↑↓ move, Enter selects, Esc closes. Highlighted row `--raised`. Match text is `--text` weight 600; rest `--text-2`.
- **No results:** one line, `No product matches "…". Try the manufacturer order number.`

### 4.4 Buttons

| Kind | Look | Use |
|---|---|---|
| **Primary** | Fill `--action`, label `--on-action` Sans 600 14, height 40 (44 on touch), padding 0 16, radius 4 | One per view: *Assess product*, *Export evidence ▾* |
| **Secondary** | Transparent, 1px `--control-border`, label `--text` Sans 500 13–14, same size | *Compare*, *Supplier questions*, *Add to comparison* |
| **Ghost / link** | No border, label `--action` Sans 500 | *Export VEX →*, *Show all findings* |
| **Segment** (filters, view toggles) | Mono 12, height 32 (44 touch), padding 0 12, radius 3. Off: transparent, `--muted`, 1px `--rule`. On: `--raised` fill, `--text`, 1px `--control-border` | Evidence filters |
| **Destructive** | Same as secondary with label and border `--avoid` | *Clear shortlist* (always confirms) |

**States:** hover — primary fill `--action-hover`; secondary border `--text`; ghost label `--action-hover`. Pressed — primary darkens 8%; others `--raised`. Focus — 2px `--action` outline, 2px offset. Disabled — fill `--raised`, label `--muted`, no border change, `cursor: not-allowed`, and a reason in the tooltip/helper text ("Export unavailable: no assessment yet"). Loading — label replaced by `Assessing…` plus a 14 px spinner; width does not change.

### 4.5 Text input

- Height 40, `--surface` fill, 1px `--control-border`, radius 4, padding 0 12, Mono 13 for identifiers (order number, firmware), Sans 14 for prose fields.
- Label above: Sans 12 `--muted`, 6 px gap. Helper text below: Sans 12 `--muted`. Error text: Sans 12 `--avoid` with a leading `■`.
- **Focus:** border `--action`. **Filled & verified:** border `--action`, small `✓` (teal) at right. **Unverified material input:** 1px **dashed** `--verify` border, label suffix `· not verified` in `--verify`, helper: "Without this the result stays VERIFY with a range." **Error:** border `--avoid`, error text below. **Disabled:** `--bar` fill, `--muted` text.
- **Firmware field is special:** it is a material input, so it is always shown with the unverified style until the user confirms a value.

### 4.6 Select, radio, checkbox, toggle

- **Select:** same box as input; chevron icon right in `--muted`. Open list is an overlay (see 4.3 popover style).
- **Checkbox:** 18 px square, radius 2, 1px `--control-border`; checked fill `--action`, check mark `--on-action`. Label Sans 14 to the right, 10 px gap, whole row clickable.
- **Radio:** 18 px circle, same colors; dot 8 px `--action`.
- **Toggle (for operating conditions such as "internet-reachable"):** 36×20 track, `--raised` off, `--action` on; knob 16 px `--text`. Always paired with a text state ("Yes / No") so state is not color alone.
- **Operating-conditions group:** a labeled fieldset on a `--surface` card; each row = label + helper left, control right; "Unknown" is always an available choice and is drawn as VERIFY-styled (dashed violet) when selected.

### 4.7 Verdict badge

Inline element, radius 3, padding 4×10, Mono 600 12, uppercase, letter-spacing .08em, `glyph + word`.

| Verdict | Text/glyph | Fill | Border |
|---|---|---|---|
| PREFER | `--prefer` | prefer @ 14% | prefer @ 50% solid |
| CONDITIONAL | `--conditional` | conditional @ 14% | conditional @ 50% solid |
| AVOID | `--avoid` | avoid @ 14% | avoid @ 50% solid |
| VERIFY | `--verify` | transparent | 1px **dashed** `--verify`; the provisional range follows the word: `? VERIFY 41–78` |

Sizes: **L** (result header, 14 px type, padding 6×12), **M** default, **S** (comparison table cells, 11 px). A badge is never a button; no hover state.

### 4.8 Score card (hero)

- Card: `--surface`, 1px `--rule`, radius 6, padding 20, 18 px vertical rhythm.
- **Top row:** panel label `PROCUREMENT SCORE · S` left; verdict badge (L) right.
- **Hero numeral:** score in Mono 500 72 px, followed by `/ 100` in Mono 14 `--muted`, baseline-aligned. The numeral is always `--text`; verdict color is carried by the badge and band bar, never by the number.
- **VERIFY:** the numeral is replaced by the headline (conservative low end) with the full range beneath: `41` large, `provisional range 41–78` Mono 13 `--verify`.
- **Mandatory blocker present:** numeric score still shown, struck through with a 1px `--muted` line and labeled `numeric score, overridden`; the badge reads AVOID.
- **Band bar** (below numeral): 10 px tall, three segments 60 / 20 / 20 in avoid / conditional / prefer at 35% alpha, radius 2. A 2×22 px `--text` marker sits at the score position. Axis row in Mono 11 `--muted`: `0 AVOID` · `60` · `80 PREFER 100`. For VERIFY, the range is drawn as a hatched 10 px bar between low and high in `--verify` over the band instead of a marker.
- **Blocker-free strip** (inset, `--bar` fill, 1px `--rule`, radius 4, padding 10×12): `✓ No mandatory blockers. No applicable KEV; no supplier restriction configured.` Teal tick, `--text` message.
- **Pillar meters** (4 rows, see 4.9).

### 4.9 Pillar meter

Row grid `28px 1fr 56px`, gap 10, vertical gap 12.

- Left: pillar key (`E`, `P`, `V`, `C`) Mono 600 14 `--action`.
- Middle: name (Sans 13) with weight right-aligned in Mono 12 `--muted` (`w .60`); beneath it a 6 px track `--raised` radius 1 and a fill.
- Right: value Mono 14 right aligned, 1 decimal.
- **Fill colors:** Exposure = verdict hue of its own value (teal ≥ 80, amber 60–79.9, coral < 60); P and V use `--action` for ordinary values; **a neutral-substituted pillar (missing evidence)** is drawn as a 6 px dashed bar `repeating-linear-gradient(90deg, violet 0 4px, transparent 4px 8px)` at 50% width, value shown as `50*`, name suffixed `· missing → neutral`, footnote `*neutral 50 applied at weight .05`.

### 4.10 Exposure table (RT8 review units)

- Card header: panel label `EXPOSURE · TOP 3 REVIEW UNITS` left; formula readout right in Mono 12: `R = min(1, Z1 + 0.20·Z2 + 0.10·Z3) = 0.417 → E = 58.3` with values bold.
- Table: Mono 13, right-aligned numerics, header row Mono 11 `--muted` uppercase `UNIT · T threat · I sev. · A reach · H impact · U unres. · Z`. Unit cell: ID in `--action` + a short Sans description in `--muted`. `Z` column is weight 600 and `--text`; other numerics `--text`.
- Row separator `--rule-row`. Row hover `--raised`. Rows are links that open the unit's evidence drawer (4.15).
- Each input header has a tooltip with the definition from the methodology ("T = strongest of KEV, LEV, EPSS, floored by vector…").
- **Floored T values** carry a small `↑` suffix with tooltip "floored by service-life vector".

### 4.11 Gap card (evidence gap)

- 1px **dashed** `--verify` border, radius 4, padding 12, 4 px internal gap. Tag line Mono 600 11 `--verify` uppercase `GAP · C`, then Sans 14 sentence. Optional action row with a ghost link: *Add certification evidence*.
- Always paired with a field in the assessment form; clicking the card scrolls to and focuses that field.
- **Context card** (informational, not a gap): same shape, solid `--rule` border, tag `CONTEXT` in `--muted`.

### 4.12 Signal chips

Inline, radius 2, padding 3×8, Mono 500 12.

| Chip | Look |
|---|---|
| `KEV` (known exploited) | Solid `--avoid` fill, `--on-avoid` text |
| `EPSS .04`, `LEV .12`, `CVSS 9.8` | `--raised` fill, 1px `#36435A`, `--text` |
| Vector (`NETWORK · wormable`, `LOCAL`, `PHYSICAL`) | Same as neutral. `wormable` text in `--conditional` |
| Fix status | Outline chip, text and 50% border in verdict hue: `Fixed in 3.1.6` teal, `Update ≥ 3.1.7` amber, `Mitigation only` coral, `Unknown` violet dashed |

Neutral chip borders are decorative; their text carries the information.

### 4.13 Blocker alert

`role="alert"`, full width of the content column, radius 4, 1px `--avoid`, fill coral @ 10%, padding 16, flex gap 14.

- Left: solid tag `BLOCKER` (Mono 700 12, `--on-avoid` on `--avoid`, radius 2, padding 4×8).
- Right: headline Sans 600 ("Known-exploited weakness applies to firmware 2.9.2"), then body Sans 14 `--text-2`: "Verdict forced to AVOID regardless of numeric score (71.8). Update to a firmware outside the affected range to clear."
- Action row: ghost link *View advisory* and secondary button *Re-assess with another version*.
- Supplier restrictions use the same component with tag `RESTRICTION`.
- Never dismissible. Appears above the score card on narrow screens.

### 4.14 Evidence (CVE) table

- Card with header row: panel label `EVIDENCE · 7 CVEs IN SCOPE FOR FW 3.1.6` left; segment filters right: `All 7`, `Unpatched 2`, `Network 5`, plus `KEV 0`. Active segment uses the "on" style from 4.4.
- Columns: `ID` (Mono, `--action`, link) · `WEAKNESS` (Sans) · `CVSS` (Mono, right) · `SIGNALS` (Mono 12 `--muted`: `EPSS .04 · LEV .12`, KEV chip if applicable) · `VECTOR` (Mono 12) · `FIX` (Mono 12 in status color).
- Row padding 12×8 (20 at the card edges); separators `--rule-row`; hover `--raised`; focus-visible 2px cyan inset ring. Header sticky inside the card scroller.
- Sort: click a header; active header shows `▲ / ▼` in `--action`. Default sort is `Z` descending, ties by CVSS.
- **Expanded row:** advisory summary, affected-range text with the firmware highlighted (Mono, `--action`), source links, and the CVE's contribution to the exposure formula.
- **Empty:** `No CVEs in scope for firmware 3.1.6. The advisories say none of their CVEs applies, so exposure is 100.` (This reflects the RT8 rule for firmware outside every affected range.)
- Footer caption Sans 12 `--muted`: "Scores support a procurement review; they are not probabilities of compromise or a certification."

### 4.15 Evidence drawer

Right-side panel, 480 px wide (full width < 640), `--surface`, left border 1px `--control-border`, overlay shadow, scrim `rgba(0,0,0,.5)`. Header: CVE ID (Mono 600, `--action`) + close button. Body sections separated by panel labels: *Summary · Affected versions · Fix · Signals · How it enters the score*. Esc closes; focus returns to the originating row; focus is trapped while open.

### 4.16 Page header block (result identity)

- Eyebrow: Mono 12 `--muted` uppercase, letter-spacing .06em: `ASSESSMENT · SIEMENS · CONTROLLER`.
- Title: Sans 600 26, product full name.
- Meta chips row (8 px gap): `MLFB 6ES7518-4AX00-1AB0`, `FW 3.1.6`, `Zone: Cell / L1`, `Service life 15 y`. Chip: Mono 12, `--surface` fill, 1px `--rule`, radius 3, padding 3×8. An unverified chip gets a dashed violet border.
- Actions right-aligned (wrap below on narrow): Secondary *Supplier questions*, Secondary *Add to comparison*, Primary *Export evidence ▾*.

### 4.17 Export menu

Opened by the primary button. Overlay list, width 240, rows 44 px: `HTML report`, `JSON`, `CSV`, `VEX`. Row = label Sans 14 + format tag Mono 11 `--muted` right. Hover `--raised`. After choosing, a toast confirms: `Exported evidence.json`.

### 4.18 Comparison (shortlist) table

- Full-width card, horizontal scroll, first column sticky (product name + order number).
- One column per candidate; rows: verdict badge (S), score (Mono 500 20), E/P/V/C values (Mono 13 with 4 px mini-bars), blockers count, gaps count, unpatched CVEs, KEV count.
- Best value in each metric gets bold `--text`; no green highlighting. Rows that contain blockers show a coral `■` left of the product name.
- Column header: product name (Sans 600), `×` remove button (32 px hit area, ≥ 44 with padding on touch), reorder by drag handle with keyboard alternative.

### 4.19 Supplier-questions panel

A card listing generated questions as a numbered list (Mono 12 `--muted` index, Sans 14 text). Each question has a linked gap tag (`GAP · C`) right-aligned and a checkbox to mark as sent. Footer: ghost *Copy all*, secondary *Export as .txt*. Empty state: "No open questions. Every material input is verified."

### 4.20 Tabs / sub-navigation inside a result

Mono 12 uppercase labels, 40 px high, gap 20; active has 2px `--action` underline and `--text`; inactive `--muted`. Tabs: *Overview · Exposure · Evidence · Questions · Inputs*.

### 4.21 Tooltips and popovers

`--raised` fill, 1px `--control-border`, radius 4, Sans 12, padding 8×10, max-width 280, 150 ms delay, shown on hover **and** focus. Never contain interactive content (use a popover or drawer for that).

### 4.22 Toasts

Bottom-left, `--surface`, 1px `--control-border`, radius 4, padding 10×14, Sans 14, left glyph in status color (`✓` teal, `■` coral). Auto-dismiss after 5 s for success; errors persist until dismissed. `role="status"` (errors `role="alert"`).

### 4.23 Loading, empty and error states

- **Loading (assessment running):** score card and table render as `--raised` blocks at final dimensions, pulsing. A mono status line reads `Resolving product… · Matching firmware… · Scoring…`. The hosted demo may be waking: after 4 s add "The hosted demo is waking up on the free plan; this can take a minute."
- **Empty (no product selected):** large search input centered in the content column, Mono sample chips below (`S7-1500`, `6ES7518-4AX00-1AB0`) that fill the field on click.
- **Product not identified:** VERIFY across the full range: `? VERIFY 0–100`, band bar fully hatched violet, explanation card "No usable evidence for this product" with the two ways forward (supply an order number, supply vendor/model).
- **Error:** inline alert (like 4.13 but with tag `ERROR` and the neutral `--rule` border) with retry button. Never replace the whole page.

### 4.24 Footer / disclaimer

Sans 12 `--muted`, top border `--rule`, padding 16×24: "ReTrust supports procurement review. It is not a probability of compromise or a certification." plus links to Methodology, Source coverage and the repository.

---

## 5. Cross-cutting behavior

### 5.1 Status mapping (single source of truth)

| Meaning | Hue | Glyph | Where it can appear |
|---|---|---|---|
| Good / resolved / fixed | `--prefer` | `●` `✓` | Verdict, fix status, snapshot dot, OK strip |
| Needs a decision / fix pending | `--conditional` | `◆` | Verdict, fix status, stale snapshot, `wormable` |
| Bad / blocking / no fix | `--avoid` | `■` | Verdict, blocker, KEV, no-fix status, errors |
| Unknown / unverified / missing | `--verify` | `?` dashed | VERIFY, gaps, unverified inputs, neutral pillars |
| Interactive | `--action` | , | Links, IDs, primary button, focus, active nav |

Using any of these hues for decoration is a design-system violation.

### 5.2 Number formatting

Score and exposure: 1 decimal. Z: 3 decimals. CVSS: 1 decimal. EPSS/LEV: 2 decimals with leading dot (`.04`). Weights: 2 decimals with leading dot. The verdict band is computed from the displayed one-decimal score (matches RT8). Ranges use an en dash: `41–78`.

### 5.3 Data and copy voice

Direct, technical, no marketing. Sentence case. State what is known and what is missing. Examples: "Certification evidence not supplied. Neutral 50 applied at weight .05." / "Confirm whether the web server is enabled on this unit." Avoid "secure", "safe", "risk-free". Never imply the score is a probability.

### 5.4 Accessibility checklist

- All text ≥ 4.5:1 (see 2.1); control borders ≥ 3:1.
- Every status has glyph + word; verified in grayscale.
- Real `<button>`, `<a>`, `<input>` + `<label>`; no clickable divs. Icon-only buttons have `aria-label`.
- Visible focus on every interactive element: 2px `--action`, 2px offset (inset ring inside tables).
- Tables use `<th scope>`; sortable headers expose `aria-sort`.
- Alerts use `role="alert"`; toasts `role="status"`.
- Drawers/menus: focus trap, Esc to close, focus returns to trigger.
- Respects `prefers-reduced-motion`.
- Minimum touch target 44 px on primary controls; text is resizable to 200% without loss.

### 5.5 Print / export (HTML report)

The exported HTML evidence report switches to a light variant: `--ground → #FFFFFF`, `--surface → #F6F8FA`, `--text → #111827`, rules `#D5DBE3`, status hues darkened to teal `#0F7A64`, amber `#8A5A00`, coral `#B42318`, violet `#5B3FC4`, action `#0B6E8E`. Layout, type and component anatomy are unchanged; verdict glyphs and words remain so black-and-white printing is lossless.

---

## 6. Do / don't

**Do**
- Show the formula inputs next to every score.
- Draw missing data dashed and violet, and give it a way to be resolved.
- Keep one primary button per view.
- Put identifiers, versions and numbers in mono.

**Don't**
- Color the score numeral or use gradients, glows or drop shadows on cards.
- Use cyan for status, or verdict hues for buttons or links.
- Hide a gap inside a tooltip, it must be visible on the card.
- Use pills, emoji, or more than 6 px of corner radius.
- Present the score as a probability or a certification.

---

## 7. Component inventory for build

`Header`, `Nav`, `GlobalSearch`, `Button` (primary/secondary/ghost/segment/destructive), `TextField`, `Select`, `Checkbox`, `Radio`, `Toggle`, `OperatingConditionsForm`, `VerdictBadge` (S/M/L), `ScoreCard`, `BandBar`, `PillarMeter`, `ExposureTable`, `GapCard`, `ContextCard`, `SignalChip`, `BlockerAlert`, `EvidenceTable`, `EvidenceDrawer`, `PageIdentity`, `ExportMenu`, `ComparisonTable`, `SupplierQuestions`, `Tabs`, `Tooltip`, `Toast`, `Skeleton`, `EmptyState`, `ErrorAlert`, `Footer`.

Reference artboards (canvas): *A · Control Room — Assessment result* and *A · Control Room — Components*.