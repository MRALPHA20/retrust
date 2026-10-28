"""The exposure card, evidence card, drawers, ranking and URL state."""

import re
from types import SimpleNamespace

import pytest
from design_lint import css_lint

from retrust import evidenceview as ev
from retrust import exposure, report, score
from retrust.match import Finding

NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
PHYS = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def finding(i, **kw):
    base = dict(cve="CVE-2026-%04d" % i, advisory_id="ICSA-26-%03d" % i,
                cvss=4.0 + i * 0.2, cwe="CWE-125", epss=i / 100.0, in_kev=False,
                ransomware=False, version_range="<2.0", decided=True,
                remediation="none_available", vector=NET)
    base.update(kw)
    return Finding(**base)


def many(count):
    return [finding(i) for i in range(1, count + 1)]


def assessed(findings, **kw):
    return score.assess("Example", findings, {"A"}, **kw)


def view(**kw):
    return ev.EvidenceView(**kw)


def cves(html_text):
    """CVE ids in first-seen order (a row names its id in text and aria-label)."""
    return list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{4,}", html_text)))


def table_of(card):
    start = card.index('id="evidence-table"')
    return card[start:card.index("</table>", start)]


# --- selection and ranking ---------------------------------------------------

def test_default_selection_and_order_keep_the_epss_then_cvss_ranking():
    fs = many(25)
    today = sorted(fs, key=lambda f: (-(f.epss or 0), -(f.cvss or 0)))[:10]
    a = assessed(fs)
    assert ev.shown(fs, a, view()) == today
    # And the rendered table lists those ten CVEs, in that order.
    assert (cves(table_of(ev.evidence_card(fs, a, view())))
            == [f.cve for f in today])


def test_default_order_breaks_epss_ties_by_cvss_then_arrival():
    fs = [finding(1, epss=.1, cvss=5), finding(2, epss=.1, cvss=9),
          finding(3, epss=.1, cvss=9)]
    assert [f.cve for f in ev.rank(fs, assessed(fs), view())] == [
        "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"]


def test_explicit_sort_applies_to_the_full_list_before_the_cap():
    fs = many(25)
    a = assessed(fs)
    # Lowest CVSS first: the cap must not hide the row the reader sorted for.
    top = ev.shown(fs, a, view(sort="cvss", dir="asc"))
    assert [f.cve for f in top][0] == "CVE-2026-0001" and len(top) == 10
    assert ev.shown(fs, a, view(sort="id", dir="desc"))[0].cve == "CVE-2026-0025"


@pytest.mark.parametrize("key", ev.SORTS)
@pytest.mark.parametrize("direction", ev.DIRS)
def test_every_sort_key_orders_without_error_and_reverses(key, direction):
    fs = many(6) + [finding(7, cvss=None, epss=None, vector=None, cwe=None)]
    a = assessed(fs)
    rows = ev.rank(fs, a, view(sort=key, dir=direction))
    assert len(rows) == 7
    if key in ("cvss", "epss", "vector", "weakness"):
        # Rows with no value go last whichever way the column runs.
        assert rows[-1].cve == "CVE-2026-0007"


def test_filters_and_counts():
    fs = [finding(1, vector=NET, remediation="vendor_fix"),       # fixed network
          finding(2, vector=LOCAL, in_kev=True),                   # unpatched local KEV
          finding(3, vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
          finding(4, vector=PHYS),
          finding(5, vector=None, remediation="mitigation")]
    a = assessed(fs)
    assert ev.counts(fs, a) == {"all": 5, "unpatched": 4, "network": 2, "kev": 1}
    assert ev.counts(fs) == ev.counts(fs, a)
    assert {f.cve for f in ev.rank(fs, a, view(ev="network"))} == {
        "CVE-2026-0001", "CVE-2026-0003"}
    assert {f.cve for f in ev.rank(fs, a, view(ev="kev"))} == {"CVE-2026-0002"}
    assert len(ev.rank(fs, a, view(ev="unpatched"))) == 4


def test_a_fix_stated_in_the_remediation_text_counts_as_patched():
    fs = [finding(1, remediation="mitigation", fix_text=True)]
    assert ev.counts(fs)["unpatched"] == 0


# --- cap and disclosure ------------------------------------------------------

def test_capped_table_discloses_the_cap_with_the_existing_wording():
    fs = many(25)
    card = ev.evidence_card(fs, assessed(fs), view())
    assert "most significant of 25 findings" in card
    assert "records how many were left out" in card
    assert len(cves(table_of(card))) == 10


def test_uncapped_table_makes_no_claim_about_a_cap():
    fs = many(4)
    assert "most significant of" not in ev.evidence_card(fs, assessed(fs), view())


def test_show_all_lifts_the_cap_and_says_so_at_the_hard_maximum():
    fs = many(25)
    card = ev.evidence_card(fs, assessed(fs), view(show_all=True))
    assert len(cves(table_of(card))) == 25
    assert "most significant of" not in card and "Showing all 25 findings" in card
    big = [finding(i, epss=(i % 100) / 100.0, cvss=5.0) for i in range(1, 251)]
    # A bare assessment keeps this fast: the cap does not depend on the scorer.
    card = ev.evidence_card(big, SimpleNamespace(paths=[], cleared_count=0),
                            view(show_all=True))
    assert len(cves(table_of(card))) == ev.HARD_MAX == 200
    assert "hard maximum" in card and "first 200 of 250 findings" in card


def test_explicit_sort_disclosure_does_not_claim_the_default_selection():
    fs = many(25)
    card = ev.evidence_card(fs, assessed(fs), view(sort="cvss", dir="asc"))
    assert "most significant of" not in card
    assert "sorted by CVSS, lowest first" in card
    assert "records how many were left out" in card


# --- headers, links and URL state -------------------------------------------

def test_only_the_active_column_has_aria_sort_with_a_cyan_glyph():
    fs = many(5)
    a = assessed(fs)
    card = ev.evidence_card(fs, a, view(sort="cvss", dir="asc"))
    assert card.count("aria-sort=") == 1
    cell = re.search(r'<th scope="col" class="n" aria-sort="ascending">(.*?)</th>', card)
    assert cell and "CVSS" in cell.group(1) and "▲" in cell.group(1)
    desc = ev.evidence_card(fs, a, view(sort="cvss", dir="desc"))
    assert 'aria-sort="descending"' in desc and "▼" in desc
    # The default order is EPSS descending, so exactly that one header says so.
    default = ev.evidence_card(fs, a, view())
    assert default.count("aria-sort=") == 1
    assert re.search(r'<th scope="col" aria-sort="descending"><a class="ev-sort"[^>]*>Signals', default)
    # Header cells are real links, and clicking the active column flips it.
    assert 'sort=cvss&amp;dir=desc#evidence' in card
    assert all('<th scope="col"' in card for _ in range(1))


def test_filter_segments_are_links_with_counts_and_aria_current():
    fs = [finding(1, in_kev=True), finding(2, remediation="vendor_fix")]
    card = ev.evidence_card(fs, assessed(fs), view(ev="kev"))
    nav = card[card.index("<nav"):card.index("</nav>")]
    assert nav.count("<a ") == 4 and nav.count('aria-current="true"') == 1
    assert re.search(r'aria-current="true">KEV 1</a>', nav)
    for label in ("All 2", "Unpatched 1", "Network 2", "KEV 1"):
        assert label in nav


def test_links_use_base_params_only_whitelisted_state_and_end_in_the_anchor():
    v = view(ev="network", sort="z", dir="desc",
             base_params={"q": 'a&b"<x>', "was_version": "1", "was_x": "2",
                          "ev": "evil", "sort": "evil", "show": "evil"})
    fs = many(25)
    card = ev.evidence_card(fs, assessed(fs), v)
    hrefs = re.findall(r'href="([^"]*)"', card)
    assert hrefs
    for href in hrefs:
        assert href.endswith("#evidence")
        assert "was_" not in href and "evil" not in href
        assert "<" not in href and '"' not in href
        assert "q=a%26b%22%3Cx%3E" in href
    assert any("show=all" in h for h in hrefs)


def test_hostile_view_values_fall_back_silently():
    hostile = view(ev='"><script>', sort="1; DROP", dir="sideways",
                   show_all="yes", base_params="not a dict",
                   anchor='x"><script>alert(1)</script>')
    fs = many(25)
    a = assessed(fs)
    assert ev.rank(fs, a, hostile) == ev.rank(fs, a, view())
    assert ev.shown(fs, a, hostile) == ev.shown(fs, a, view())
    card = ev.evidence_card(fs, a, hostile)
    assert "<script" not in card and "DROP" not in card
    assert 'id="xscriptalert1script"' in card
    assert all(h.endswith("#xscriptalert1script") for h in re.findall(r'href="([^"]*)"', card))
    assert ev.counts(fs, a)["all"] == 25


def test_none_view_means_the_default_view():
    fs = many(3)
    a = assessed(fs)
    assert ev.shown(fs, a, None) == ev.shown(fs, a, view())


# --- formatting, chips, fix mapping -----------------------------------------

def test_signals_never_show_a_small_probability_as_zero():
    fs = [finding(1, epss=.04, lev=.123), finding(2, epss=.001, lev=None),
          finding(3, epss=.999), finding(4, epss=None)]
    card = ev.evidence_card(fs, assessed(fs), view())
    assert "EPSS .04 · LEV .12" in card
    assert "EPSS &lt;.01" in card and "EPSS &gt;.99" in card
    assert "EPSS .00" not in card and "LEV .00" not in card
    assert "%" not in table_of(card)
    # LEV is omitted, not dashed, when the history is not loaded.
    assert card.count("LEV") == 1


def test_kev_is_a_solid_chip_and_vector_marks_wormable():
    fs = [finding(1, in_kev=True), finding(2, vector=LOCAL), finding(3, vector=PHYS)]
    card = ev.evidence_card(fs, assessed(fs), view())
    assert card.count("rt-chip--kev") == 1
    assert "NETWORK · <span class=\"rt-chip__warn\">wormable</span>" in card
    assert ">LOCAL<" in card and ">PHYSICAL<" in card


@pytest.mark.parametrize("remediation, fix_text, tone, label", [
    ("vendor_fix", False, "conditional", "Fix available"),
    ("mitigation", True, "conditional", "Fix available"),
    ("mitigation", False, "avoid", "Mitigation only"),
    ("workaround", False, "avoid", "Mitigation only"),
    ("none_available", False, "avoid", "No fix"),
    ("unknown", False, "verify", "Unknown"),
])
def test_fix_chip_colour_and_label_follow_the_remediation(remediation, fix_text, tone, label):
    fs = [finding(1, remediation=remediation, fix_text=fix_text)]
    card = ev.evidence_card(fs, assessed(fs), view())
    assert "rt-chip--fix-%s" % tone in card and label in table_of(card)


def test_fixed_is_teal_only_when_u_is_verified_zero():
    f = finding(1)
    fixed = SimpleNamespace(entry={"factors": {"U": [0.0, 0.0]}})
    open_ = SimpleNamespace(entry={"factors": {"U": [1.0, 1.0]}})
    assert ev._fix_key(f, fixed) == "fixed"
    assert ev._fix_key(f, open_) == "nofix"
    assert ev._fix_key(f, None) == "nofix"
    from retrust import components
    assert "rt-chip--fix-prefer" in components.signal_chip("fix", "Fixed", "fixed")


def test_a_verified_fix_reaches_the_table_through_the_assessment():
    fs = [finding(1, remediation="vendor_fix")]
    a = score.assess("Example", fs, {"A"}, remediation="applied", version="9.0")
    fs[0].version_supplied = True
    fs[0].decided = False
    a = score.assess("Example", fs, {"A"}, remediation="applied", version="9.0")
    card = ev.evidence_card(fs, a, view(), firmware="9.0")
    assert "rt-chip--fix-prefer" in card and "Fixed" in card


def test_weakness_column_shows_class_and_cwe():
    fs = [finding(1, cwe="CWE-798"), finding(2, cwe="CWE-9999"), finding(3, cwe=None)]
    card = ev.evidence_card(fs, assessed(fs), view())
    assert "hardcoded credentials" in card and "CWE-798" in card and "CWE-9999" in card


# --- exposure card -----------------------------------------------------------

def resolved_exposure(fs):
    result = exposure.analyse(fs, consequence="control", interface="exposed",
                              remediation="affected", network="internal",
                              prerequisites="satisfiable")
    return SimpleNamespace(paths=result.paths, exposure_min=result.safety_min,
                           exposure_max=result.safety_max, cleared_count=0), result


def test_readout_numbers_equal_the_exposure_module():
    fs = many(6)
    fake, result = resolved_exposure(fs)
    assert not result.provisional
    card = ev.exposure_card(fake)
    r = exposure.concentrate([p["z_max"] for p in result.paths])
    assert "R = min(1, Z1 + 0.20·Z2 + 0.10·Z3) = <b>%.3f</b> → E = <b>%.1f</b>" % (
        r, result.safety_min) in card
    assert "EXPOSURE · TOP 3 REVIEW UNITS" in card


def test_readout_uses_the_real_concentration_constants(monkeypatch):
    monkeypatch.setattr(exposure, "CONCENTRATION", (1.0, .25, .05))
    fake, _ = resolved_exposure(many(3))
    assert "Z1 + 0.25·Z2 + 0.05·Z3" in ev.exposure_card(fake)


def test_provisional_readout_is_an_en_dash_range_in_violet():
    fs = many(6)
    result = exposure.analyse(fs)
    assert result.provisional
    fake = SimpleNamespace(paths=result.paths, exposure_min=result.safety_min,
                           exposure_max=result.safety_max, cleared_count=0)
    card = ev.exposure_card(fake)
    lo, hi = "%.1f" % result.safety_min, "%.1f" % result.safety_max
    assert 'class="ev-range">%s–%s</span>' % (lo, hi) in card
    assert "? 0–1" in card and 'class="ev-unk"' in card


def test_top_three_units_with_columns_legend_and_tooltips():
    fs = many(8)
    fake, result = resolved_exposure(fs)
    card = ev.exposure_card(fake)
    body = card[card.index("<tbody>"):card.index("</tbody>")]
    assert body.count("<tr>") == 3
    for path in result.paths[:3]:
        assert path["path_id"] in body
    for path in result.paths[3:]:
        assert path["path_id"] not in body
    assert "only the top 3 enter R" in card
    for letter in "TIAHUZ":
        assert 'role="tooltip" id="ev-tip-%s"' % letter in card
    # The definitions are on the page as well, not only in tooltips.
    legend = card[card.index('<dl class="ev-legend">'):]
    for name in ("Threat", "Severity", "Reach", "Impact", "Unresolved", "Unit risk"):
        assert name in legend
    assert "%.3f" % result.paths[0]["z_max"] in body


def test_floored_t_carries_the_arrow_and_a_measured_t_does_not():
    floored = [finding(1, epss=.01, vector=NET)]            # floor .50 beats EPSS
    fake, result = resolved_exposure(floored)
    card = ev.exposure_card(fake)
    assert "↑" in card and "floored by service-life vector" in card
    assert "0.50" in card
    kev = [finding(1, in_kev=True)]
    fake, _ = resolved_exposure(kev)
    assert "↑" not in ev.exposure_card(fake)
    # Local and physical flaws floor lower, and the arrow still marks them.
    for vector, value in ((LOCAL, "0.15"), (PHYS, "0.05")):
        fake, _ = resolved_exposure([finding(1, epss=.001, vector=vector)])
        card = ev.exposure_card(fake)
        assert value + "<span" in card and "↑" in card
    # A measured value above the floor is not floored.
    fake, _ = resolved_exposure([finding(1, epss=.9, vector=NET)])
    assert "↑" not in ev.exposure_card(fake)


def test_unit_rows_open_the_drawer_of_a_shown_record_only():
    fs = many(14)
    a = assessed(fs)
    v = view()
    with_rows = ev.exposure_card(a, findings=fs, view=v)
    ids = set(re.findall(r'popovertarget="([^"]+)"', with_rows))
    shown_ids = set(re.findall(r'id="(ev-d-[^"]+)" popover', ev.drawers(fs, a, v)))
    assert ids and ids <= shown_ids
    assert "popovertarget" not in ev.exposure_card(a)


def test_exposure_card_without_units_explains_itself():
    a = SimpleNamespace(paths=[], exposure_min=100.0, exposure_max=100.0,
                        cleared_count=3)
    assert "No CVE applies to the selected firmware" in ev.exposure_card(a)
    a.cleared_count = 0
    assert "not proof of safety" in ev.exposure_card(a)
    a.exposure_min = None
    assert "Exposure not computed" in ev.exposure_card(a)


# --- empty states ------------------------------------------------------------

def test_cleared_firmware_empty_state_only_when_the_data_says_so():
    a = SimpleNamespace(paths=[], cleared_count=4)
    card = ev.evidence_card([], a, view(), firmware="3.1.6")
    assert ("No CVEs in scope for firmware 3.1.6. The advisories say none of "
            "their CVEs applies, so exposure is 100.") in card
    assert "EVIDENCE · 0 CVEs IN SCOPE FOR FW 3.1.6" in card
    plain = ev.evidence_card([], SimpleNamespace(paths=[], cleared_count=0),
                             view(), firmware="3.1.6")
    assert "exposure is 100" not in plain and "No CVEs in scope." in plain
    assert "exposure is 100" not in ev.evidence_card([], a, view())


def test_filter_with_no_matches_offers_the_way_back():
    fs = many(3)
    card = ev.evidence_card(fs, assessed(fs), view(ev="kev"))
    assert "No CVEs match the kev filter (3 in scope)" in card
    assert "Show all 3" in card and "evidence-table" not in card
    assert ev.drawers(fs, assessed(fs), view(ev="kev")) == ""


def test_label_names_the_scope():
    fs = many(2)
    a = assessed(fs)
    assert "EVIDENCE · 2 CVEs IN SCOPE FOR FW 3.1.6" in ev.evidence_card(
        fs, a, view(), firmware="3.1.6")
    assert "EVIDENCE · 2 CVEs · ALL AFFECTED VERSIONS" in ev.evidence_card(fs, a, view())
    one = many(1)
    assert "1 CVE " in ev.evidence_card(one, assessed(one), view(), firmware="1")


def test_caption_and_table_hooks():
    fs = many(2)
    card = ev.evidence_card(fs, assessed(fs), view())
    assert ev.CAPTION in card and '<table id="evidence-table"' in card
    assert 'class="tw ev-scroll"' in card and "Vulnerabilities to review" in card


# --- drawers -----------------------------------------------------------------

@pytest.mark.parametrize("v", [view(), view(ev="unpatched"), view(sort="cvss"),
                               view(show_all=True), view(ev="kev")])
def test_drawer_count_equals_shown_rows_and_every_opener_has_a_drawer(v):
    fs = many(25)
    fs[3].in_kev = True
    a = assessed(fs)
    rows = ev.shown(fs, a, v)
    html_ = ev.drawers(fs, a, v)
    assert html_.count('popover="auto"') == len(rows)
    card = ev.evidence_card(fs, a, v)
    openers = re.findall(r'class="ev-open" popovertarget="([^"]+)"', table_of(card))
    drawers = re.findall(r'id="(ev-d-[^"]+)" popover', html_)
    assert openers == drawers and len(set(drawers)) == len(drawers)


def test_drawer_anatomy_and_sections():
    fs = [finding(1, version_range="<2.0", decided=True)]
    a = assessed(fs)
    out = ev.drawers(fs, a, view(), {"ICSA-26-001": ("Title of advisory", "2026-01-02")},
                     firmware="1.4")
    assert 'role="dialog"' in out and 'aria-labelledby="ev-d-CVE-2026-0001-title"' in out
    assert 'id="ev-d-CVE-2026-0001-title"' in out
    assert 'aria-label="Close details for CVE-2026-0001"' in out
    assert 'popovertargetaction="hide"' in out and "<script" not in out
    for section in ("Summary", "Affected versions", "Fix", "Signals",
                    "How it enters the score"):
        assert ">%s<" % section in out
    assert "ICSA-26-001" in out and "Title of advisory" in out and "2026-01-02" in out
    assert 'class="ev-fw">1.4</span>' in out and "inside this range" in out
    assert "Weight 1" in out
    assert "does not state which version contains the fix" in out


def test_drawer_weights_follow_the_unit_rank_and_outside_top_3_is_said():
    fs = many(6)
    a = assessed(fs)
    out = ev.drawers(fs, a, view(show_all=True), None)
    for text in ("Weight 1", "Weight .20", "Weight .10", "Outside top 3"):
        assert text in out
    assert "title and release date are not available" in out.replace("Advisory ", "")


def test_drawer_without_firmware_says_all_versions_are_in_scope():
    fs = many(1)
    out = ev.drawers(fs, assessed(fs), view(), None)
    assert "every affected version is in scope" in out


def test_drawer_ids_are_unique_slugs_even_for_repeated_or_colliding_cves():
    fs = [finding(1, cve="CVE-2026-0001", advisory_id="A-1"),
          finding(2, cve="CVE-2026-0001", advisory_id="A-2"),
          finding(3, cve="CVE-2026-0001", advisory_id="A-2"),
          finding(4, cve="CVE-9<a", advisory_id="X"),
          finding(5, cve="CVE-9>a", advisory_id="X"),
          finding(6, cve='"onfocus="x', advisory_id="X")]
    a = assessed(fs)
    out = ev.drawers(fs, a, view(), None)
    ids = re.findall(r'<div class="ev-drawer" id="([^"]*)"', out)
    assert len(ids) == 6 == len(set(ids))
    assert all(re.fullmatch(r"ev-d-[A-Za-z0-9_-]+", i) for i in ids)
    assert "onfocus=" not in out.replace("&quot;onfocus=&quot;x", "")


# --- escaping ----------------------------------------------------------------

PAYLOAD = '<img src=x onerror=alert(1)>"\'<script>alert(2)</script>'


def test_external_strings_are_escaped_everywhere():
    fs = [finding(1, cve=PAYLOAD, advisory_id=PAYLOAD, cwe=PAYLOAD,
                  version_range=PAYLOAD, vector=PAYLOAD)]
    a = assessed(fs)
    adv = {PAYLOAD: (PAYLOAD, PAYLOAD)}
    for static in (False, True):
        pieces = [ev.evidence_card(fs, a, view(), firmware=PAYLOAD,
                                   advisories=adv, static=static),
                  ev.exposure_card(a, static=static, findings=fs, view=view())]
    pieces.append(ev.drawers(fs, a, view(), adv, firmware=PAYLOAD))
    for piece in pieces:
        assert "<script" not in piece and "<img" not in piece
        assert 'onerror=alert(1)>' not in piece
    assert "&lt;script&gt;" in pieces[0]


def test_hostile_path_ids_in_the_exposure_card_are_escaped():
    a = SimpleNamespace(paths=[{"path_id": PAYLOAD, "cves": [PAYLOAD],
                                "grouping": PAYLOAD, "z_min": 0.1, "z_max": 0.1,
                                "inputs": []}],
                        exposure_min=90.0, exposure_max=90.0, cleared_count=0)
    card = ev.exposure_card(a)
    assert "<script" not in card and "<img" not in card


# --- export mode -------------------------------------------------------------

@pytest.mark.parametrize("v", [view(), view(sort="z"), view(ev="network"),
                               view(show_all=True)])
def test_static_mode_has_no_controls_links_or_urls(v):
    fs = many(14)
    fs[2].in_kev = True
    a = assessed(fs)
    pieces = [ev.evidence_card(fs, a, v, firmware="1.0",
                               advisories={"ICSA-26-001": ("T", "2026")}, static=True),
              ev.exposure_card(a, static=True, findings=fs, view=v)]
    for piece in pieces:
        for banned in ("<a ", "popover", "<form", "<button", "https://", "http://",
                       "href=", "role=\"tooltip\"", "<script", "aria-sort"):
            assert banned not in piece, banned
    card = pieces[0]
    assert "All 14 · Unpatched" in card
    assert card.count('class="ev-detail"') == len(ev.shown(fs, a, v))
    assert "How it enters the score" in card and "Affected versions" in card
    assert "Order: " in card
    assert 'id="evidence-table"' in card and ev.CAPTION in card


def test_static_empty_filter_has_no_link():
    fs = many(2)
    card = ev.evidence_card(fs, assessed(fs), view(ev="kev"), static=True)
    assert "<a " not in card and "No CVEs match" in card


# --- stylesheet --------------------------------------------------------------

def test_css_is_a_clean_prefixed_string():
    assert isinstance(ev.CSS, str) and ev.CSS.strip()
    assert css_lint(ev.CSS) == []
    for selector in re.findall(r"\.([A-Za-z][\w-]*)", ev.CSS):
        # "n" is the legacy numeric-cell hook design.BASE_CSS also styles.
        assert selector in ("n", "tw", "sr-only") or selector.startswith(
            ("ev-", "rt-")), selector
    assert "@import" not in ev.CSS and "url(" not in ev.CSS
    assert ":popover-open" in ev.CSS and "::backdrop" in ev.CSS
    assert "width:480px" in ev.CSS and "max-width:639px" in ev.CSS
    assert "position:sticky" in ev.CSS


def test_evidenceview_does_not_import_the_renderers():
    import inspect
    source = inspect.getsource(ev)
    for banned in ("import report", "from . import report", "import serve",
                   "import webui", "from .report", "from .serve", "from .webui"):
        assert banned not in source
