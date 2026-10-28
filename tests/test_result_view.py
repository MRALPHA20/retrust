"""Result composites and the light export (WP5a).

evidenceview is faked with marker strings so none of this depends on WP5b.
"""
import re
from html.parser import HTMLParser

import pytest

from design_lint import css_lint
from retrust import components, evidenceview, report, score, serve, supplychain
from retrust.match import Finding, Match, Resolution

EXPOSURE = "<!--EXPOSURE-->"
EVIDENCE = "<!--EVIDENCE-->"


@pytest.fixture(autouse=True)
def fake_evidence(monkeypatch):
    calls = {}

    def exposure_card(assessment, *, static=False, findings=None, view=None):
        calls["exposure"] = dict(static=static, findings=findings, view=view)
        return EXPOSURE

    def evidence_card(findings, assessment, view, *, firmware="", advisories=None,
                      static=False):
        calls["evidence"] = dict(static=static, firmware=firmware, advisories=advisories)
        return EVIDENCE

    def drawers(findings, assessment, view, advisories=None, *, firmware=""):
        calls["drawers"] = dict(firmware=firmware)
        return '<div id="ev-d-CVE-2026-0001" popover></div>'

    monkeypatch.setattr(evidenceview, "exposure_card", exposure_card)
    monkeypatch.setattr(evidenceview, "evidence_card", evidence_card)
    monkeypatch.setattr(evidenceview, "drawers", drawers)
    return calls


def finding(**kw):
    base = dict(cve="CVE-2026-0001", advisory_id="A", cvss=7.5, cwe=None, epss=.04,
                in_kev=False, ransomware=False, version_range="<2", decided=True,
                remediation="vendor_fix")
    base.update(kw)
    return Finding(**base)


def resolved(vendor="Siemens"):
    match = Match(advisory_id="A", vendor=vendor, name="PLC", version_range="", cves=[]) \
        if False else None
    res = Resolution(query="x", method="exact_name", confidence=.9)
    res.matches = [type("M", (), {"vendor": vendor, "name": "PLC", "advisory_id": "A"})()]
    return res


def unresolved():
    return Resolution(query="x", abstained=True, reason="vendor not in corpus")


def verify(**kw):
    fields = dict(product="PLC", verdict="VERIFY", score=41.3, score_min=41.3,
                  score_max=78.2, provisional=True, exposure_min=20.0,
                  exposure_max=80.0, confidence=.5, findings_count=3,
                  vector="RT8/AT:purchase/FW:3.1.6/NX:unset")
    fields.update(kw)
    return score.Assessment(**fields)


def pillars(**scored):
    out = []
    for name, value in (("Exposure", 58.3), ("Patch availability", 80.0),
                        ("Vendor practice", 70.0), ("Certification", 0.0)):
        out.append(score.Pillar(name, value, 1.0, [f"{name} evidence line"],
                                scored=scored.get(name, True)))
    return out


def block(assessment, resolution=None, findings=(), **kw):
    return report._assessment_block(assessment, resolution, findings, **kw)


def text(markup):
    return " ".join(re.sub(r"<[^>]+>", " ", markup).split())


# --- score card states ---------------------------------------------------------

def test_verify_shows_the_low_end_range_and_a_hatched_bar():
    markup = block(verify())
    assert "Provisional range 41.3–78.2" in markup
    assert 'rt-score__num">41.3<' in markup
    assert "rt-band__range" in markup and "rt-band__marker" not in markup
    assert "rt-badge--verify" in markup and "VERIFY" in markup


def test_the_numeral_is_never_a_verdict_colour():
    css = report.RESULT_CSS
    rule = re.search(r"\.rt-score__num\{[^}]*\}", css).group()
    assert "color:var(--text)" in rule
    assert "--prefer" not in rule and "--avoid" not in rule and "--verify" not in rule


def test_avoid_with_gates_and_a_score_strikes_the_numeral():
    gate = {"gate": "Known exploited vulnerability", "detail": "1 CVE(s): CVE-2026-0001",
            "source": "CISA"}
    markup = block(score.Assessment(product="PLC", verdict="AVOID", score=71.8,
                                    gates=[gate], pillars=pillars()))
    assert "rt-score__num--struck" in markup
    assert "numeric score, overridden" in markup
    assert "numeric score (71.8)" in markup
    assert "rt-band__marker--overridden" in markup


def test_avoid_without_a_score_says_disqualified():
    gate = {"gate": supplychain.COVERED_LIST_GATE, "detail": "x", "source": "s"}
    markup = block(score.blocked("Cam", [gate], "vendor not in corpus"), unresolved())
    assert "&mdash;" in markup and "disqualified below" in markup
    assert "numeric score (none computed)" in markup
    assert "not enough data" not in markup
    assert "rt-band__marker" not in markup


def test_not_identified_shows_the_real_range_and_the_two_ways_forward():
    assessment = score.not_assessed("Unknown PLC", "vendor not in corpus")
    markup = block(assessment, unresolved())
    low, high = assessment.score_min, assessment.score_max
    assert (low, high) != (0, 100)
    assert f"Provisional range {low:.1f}–{high:.1f}" in markup
    assert "range 0.0–100.0" not in markup
    assert "No usable evidence for this product" in markup
    assert "Enter the manufacturer order number" in markup
    assert "Enter the vendor and the exact model name" in markup
    for kept in ("product not identified", "Not identified.",
                 "Check the manufacturer order number, vendor and model"):
        assert kept in " ".join(markup.split())
    assert "rt-strip" not in markup           # nothing was assessed to be free of blockers


# --- pillar meters ---------------------------------------------------------------

def test_neutral_pillar_is_dashed_fifty_with_the_real_weight():
    a = verify(provisional=False, score_min=None, score_max=None, exposure_min=None,
               exposure_max=None, score=62.0, verdict="CONDITIONAL",
               pillars=pillars(Certification=False))
    markup = block(a, weights=score.DEFAULT_WEIGHTS)
    assert "50*" in markup
    assert "· missing → neutral" in markup
    assert "rt-pillar__fill--neutral" in markup and 'style="width:50%"' in markup
    assert "*neutral 50 applied at weight .05" in markup
    assert "Certification evidence: no usable evidence" in markup
    assert "GAP · C" in markup


def test_neutral_footnote_uses_the_configured_weight():
    a = verify(provisional=False, score=62.0, verdict="CONDITIONAL", exposure_min=None,
               exposure_max=None, score_min=None, score_max=None,
               pillars=pillars(Certification=False))
    weights = {"exposure": .5, "patchability": .2, "vendor_practice": .1, "certification": .2}
    assert "*neutral 50 applied at weight .20" in block(a, weights=weights)


def test_provisional_exposure_is_solid_to_low_then_hatched():
    markup = block(verify(pillars=pillars()), weights=score.DEFAULT_WEIGHTS)
    assert "rt-pillar__fill--hatch" in markup
    assert "20.0–80.0" in markup


def test_weights_shown_equal_the_exponents_the_composite_applies():
    weights = {"exposure": 3.0, "patchability": 1.0, "vendor_practice": 1.0,
               "certification": 1.0}
    shares = {spec.name: report._weight_share(spec.name, weights) for spec in score.PILLARS}
    assert shares["Exposure"] == pytest.approx(.5)
    assert sum(shares.values()) == pytest.approx(1.0)
    usable = [(spec, score.Pillar(spec.name, 40.0 + 10 * i, 1.0))
              for i, spec in enumerate(score.PILLARS)]
    expected = 1.0
    for (spec, pillar) in usable:
        expected *= pillar.score ** shares[spec.name]
    assert score._composite(usable, weights) == pytest.approx(expected)
    # A missing pillar does not renormalise the others.
    assert report._weight_share("Exposure", weights, active_pillars=[]) == pytest.approx(.5)
    a = verify(provisional=False, score=62.0, verdict="CONDITIONAL", exposure_min=None,
               exposure_max=None, score_min=None, score_max=None,
               pillars=pillars(Certification=False))
    markup = block(a, weights=weights)
    assert "w .50" in markup and "w .17" in markup


# --- blockers --------------------------------------------------------------------

@pytest.mark.parametrize("label,tag", [
    (supplychain.COVERED_LIST_GATE, "RESTRICTION"),
    (supplychain.SANCTIONS_GATE, "RESTRICTION"),
    ("Known exploited vulnerability", "BLOCKER"),
    ("Ransomware-linked vulnerability", "BLOCKER")])
def test_gate_tag_and_role(label, tag):
    a = score.blocked("P", [{"gate": label, "detail": "d", "source": "s"}], "r")
    markup = block(a)
    assert f"</span> {tag}</span>" in markup
    assert 'role="alert"' in markup
    assert "Purchase blocker" in markup
    assert "Verdict forced to AVOID regardless of numeric score" in markup
    assert "dismiss" not in markup.lower() and "close" not in markup.lower()


def test_gate_labels_are_the_supplychain_constants():
    assert supplychain.COVERED_LIST_GATE == "Named on a covered list"
    assert supplychain.SANCTIONS_GATE == "Sanctioned or export-restricted entity"
    assert report.RESTRICTION_GATES == {supplychain.COVERED_LIST_GATE,
                                        supplychain.SANCTIONS_GATE}


def test_web_blocker_offers_the_advisory_and_a_reassess_link():
    gate = {"gate": "Known exploited vulnerability",
            "detail": "1 CVE(s) are affected: CVE-2026-0001", "source": "CISA"}
    a = score.Assessment(product="P", verdict="AVOID", score=50.0, gates=[gate])
    web = report.WebView(field_ids={"version": "f-fw"})
    markup = block(a, web=web)
    assert 'popovertarget="ev-d-CVE-2026-0001"' in markup
    assert 'href="#f-fw"' in markup and "Re-assess with another version" in markup
    export = block(a)
    assert "popovertarget" not in export and "Re-assess" not in export


def test_a_restriction_has_no_version_action():
    a = score.blocked("P", [{"gate": supplychain.SANCTIONS_GATE, "detail": "d",
                             "source": "s"}], "r")
    assert "Re-assess" not in block(a, web=report.WebView())


# --- the blocker-free strip is honest ---------------------------------------------

def clean():
    return verify(provisional=False, score=88.0, verdict="PREFER", score_min=None,
                  score_max=None, exposure_min=None, exposure_max=None,
                  pillars=pillars())


def test_strip_claims_only_checks_that_ran():
    both = block(clean(), web=report.WebView(
        checks={"kev_loaded": True, "screening_loaded": True}))
    assert ("✓</span> <span>No mandatory blockers. No KEV-listed CVE in the device firmware forces AVOID. "
            "No supplier screening match.") in both
    kev_only = block(clean(), web=report.WebView(
        checks={"kev_loaded": True, "screening_loaded": False}))
    assert "No KEV-listed CVE in the device firmware forces AVOID." in kev_only
    assert "No supplier restriction configured" not in kev_only
    assert "Supplier screening list not loaded" in kev_only
    assert "No mandatory blockers in the checks that ran." in kev_only
    neither = block(clean(), web=report.WebView(
        checks={"kev_loaded": False, "screening_loaded": False}))
    assert "rt-strip" not in neither and "✓" not in neither
    assert "KEV list not loaded" in neither


def test_strip_is_absent_when_nothing_is_known_or_gated():
    assert "rt-strip" not in block(clean(), web=report.WebView())
    assert "rt-strip" not in block(clean())
    gate = {"gate": "Known exploited vulnerability", "detail": "d", "source": "s"}
    gated = score.Assessment(product="P", verdict="AVOID", score=50.0, gates=[gate])
    assert "rt-strip" not in block(gated, web=report.WebView(
        checks={"kev_loaded": True, "screening_loaded": True}))


def test_export_derives_kev_loaded_from_provenance():
    blocks = [(clean(), resolved(), [])]
    with_kev = report.render(blocks, provenance=[
        {"source": "CISA KEV", "detail": "d", "captured": "2026-10-01"}])
    assert "No KEV-listed CVE in the device firmware forces AVOID." in with_kev
    assert "No supplier restriction" not in with_kev
    without = report.render(blocks, provenance=[
        {"source": "FIRST EPSS", "detail": "d", "captured": "2026-10-01"}])
    assert "KEV list not loaded" in without and "No KEV-listed CVE" not in without
    assert 'class="rt-strip"' not in report.render(blocks)


# --- order, grid, gaps -------------------------------------------------------------

def test_dom_order_in_web_mode():
    a = verify(pillars=pillars(), cautions=[{"caution": "x", "detail": "d", "source": "s"}],
               verification=['Answer "Network exposure" -- context'])
    web = report.WebView(actions_html="<!--ACTIONS-->", tabs_html="<!--TABS-->",
                         questions_html="<!--QUESTIONS-->", inputs_html="<!--INPUTS-->")
    gate = {"gate": "Known exploited vulnerability", "detail": "d", "source": "s"}
    a.gates = [gate]
    markup = block(a, [][:0] or None, [finding()], tools="<!--TOOLS-->", web=web)
    order = ["rt-identity", "<!--ACTIONS-->", "<!--TABS-->", "rt-alerts", 'class="rt-grid"',
             "rt-score", EXPOSURE, "What to check next", "Supplier review needed",
             "<!--TOOLS-->", EVIDENCE, "<!--QUESTIONS-->", "<!--INPUTS-->",
             "assessment-more-info", 'id="ev-d-CVE-2026-0001"']
    positions = [markup.index(token) for token in order]
    assert positions == sorted(positions), list(zip(order, positions))
    assert markup.index("Procurement score") < markup.index(EXPOSURE)


def test_fakes_receive_the_contract_arguments(fake_evidence):
    web = report.WebView(version="3.1.6", advisories={"A": ("t", "d")})
    block(verify(), None, [finding()], web=web)
    assert fake_evidence["exposure"]["findings"] and fake_evidence["exposure"]["view"] is web.evidence
    assert fake_evidence["evidence"]["firmware"] == "3.1.6"
    assert fake_evidence["drawers"]["firmware"] == "3.1.6"
    assert fake_evidence["evidence"]["static"] is False


def test_the_layout_is_one_column_then_one_to_two():
    css = report.RESULT_CSS
    assert "@media (min-width:1100px){.rt-grid{grid-template-columns:minmax(380px,1fr) minmax(0,2fr)}}" in css
    assert re.search(r"\.rt-grid\{display:grid;grid-template-columns:minmax\(0,1fr\)", css)


def test_gap_rules_map_phrases_to_form_fields():
    assert report.GAP_RULES == serve.OPEN_QUESTIONS
    fields = {field for _, field in report.GAP_RULES}
    assert fields == {"network_exposure", "interface", "prerequisites", "consequence",
                      "remediation", "version"}
    assert report._gap_for('Answer "Network exposure" -- x')[0] == "network_exposure"
    assert report._gap_for("Re-check the version")[0] == "version"
    assert report._gap_for("Exploitation data is missing for these")[:2] == ("", "T")


def test_gap_cards_link_to_fields_on_the_web_only():
    a = verify(verification=['Answer "Network exposure" -- context'])
    web = report.WebView(field_ids={"network_exposure": "f-net"})
    assert 'href="#f-net"' in block(a, web=web)
    assert "GAP · ZONE" in block(a)
    assert 'href="#f-net"' not in block(a)


def test_missing_firmware_gets_a_fw_gap_and_neutral_pillars_have_no_form_field():
    a = verify(provisional=False, score=62.0, verdict="CONDITIONAL", vector="RT8/FW:unset",
               exposure_min=None, exposure_max=None, score_min=None, score_max=None,
               pillars=pillars(Certification=False))
    markup = block(a, resolved("Moxa"), web=report.WebView())
    assert "GAP · FW" in markup and 'href="#field-version"' in markup
    assert 'href="/vendor?name=Moxa"' in markup
    assert "/vendor" not in block(a, resolved("Moxa"))


# --- identity ----------------------------------------------------------------------

def test_identity_chips_and_omitted_fields():
    a = verify(network_exposure="ot_only")
    web = report.WebView(order_number="6ES7518", version="3.1.6")
    markup = block(a, resolved("Siemens"), [finding(decided=False)], web=web)
    assert "Assessment · Siemens" in markup
    assert "Order no. 6ES7518" in markup
    assert re.search(r'rt-meta--unverified"><span aria-hidden="true">\?</span> FW 3\.1\.6', markup)
    assert "Zone: OT network only" in markup
    assert "Service life" not in markup and "CONTROLLER" not in markup
    firm = block(a, resolved(), [finding(decided=True)], web=web)
    assert re.search(r'<span class="rt-meta">FW 3\.1\.6', firm)
    assert "FW not given" in block(verify(vector="RT8/FW:unset"))


# --- export ------------------------------------------------------------------------

class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs = [], set()

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.update(name for name, _ in attrs)


def export(**kw):
    a = score.Assessment(product="PLC", verdict="AVOID", score=71.8,
                         pillars=pillars(), cautions=[{
                             "caution": "KEV-listed CVEs in third-party component bundles",
                             "detail": "CVE-2026-0002 see https://example.org/x",
                             "source": "https://vendor.example/advisory"}],
                         third_party_count=2, first_party_count=1, notes=["see http://n.example"],
                         gates=[{"gate": "Known exploited vulnerability",
                                 "detail": "CVE-2026-0001", "source": "https://cisa.gov/kev"}])
    return report.render([(a, resolved(), [finding()])], provenance=[
        {"source": "CISA KEV", "detail": "d", "captured": "2026-10-01"}], **kw)


def test_export_has_no_controls_links_or_external_references():
    markup = export()
    parser = Tags()
    parser.feed(markup)
    for tag in ("form", "dialog", "script", "img", "input", "button", "select"):
        assert tag not in parser.tags, tag
    assert "popovertarget" not in parser.attrs and "popover" not in parser.attrs
    assert not any(a.startswith("on") for a in parser.attrs)
    for forbidden in ("http://", "https://", "@import", "prefers-color-scheme"):
        assert forbidden not in markup, forbidden
    assert 'href="' not in markup
    assert "<dl>" in markup and "Terms used in this report" in markup
    assert EXPOSURE in markup and EVIDENCE in markup
    assert markup.index(":root{--ground:#FFFFFF") < markup.index(":root[data-theme=dark]{")


def test_export_stylesheet_order():
    css = report.export_css()
    order = [css.index(":root{--ground"), css.index(":root[data-theme=dark]"),
             css.index("@font-face"), css.index(".t-score"), css.index(".rt-badge{"),
             css.index(".rt-score{"), css.index(".rt-glossary")]
    assert order == sorted(order)


def test_export_shows_cautions_and_notes_statically():
    markup = export()
    assert "<details><summary>Which vulnerabilities" not in markup
    assert "Supplier review needed" in markup and 'role="alert"' in markup


def test_web_cautions_are_collapsible_and_not_assertive():
    a = verify(cautions=[{"caution": "x", "detail": "d", "source": "s"}])
    markup = block(a, web=report.WebView())
    assert "<details><summary>Which vulnerabilities and sources?</summary>" in markup
    review = markup[markup.index("rt-alert--review"):]
    assert 'role="alert"' not in review.split(">")[0]


# --- safety and styles -------------------------------------------------------------

def test_hostile_strings_are_escaped_everywhere():
    evil = '<img src=x onerror=alert(1)>"\''
    a = verify(product=evil, notes=[evil], verification=[evil],
               gates=[{"gate": evil, "detail": evil, "source": evil}],
               cautions=[{"caution": evil, "detail": evil, "source": evil}])
    res = resolved(evil)
    res.reason = evil
    markup = report.render([(a, res, [finding()])], title=evil)
    assert "<img" not in markup
    assert "&lt;img src=x onerror=alert(1)&gt;" in markup


@pytest.mark.parametrize("name", ["RESULT_CSS", "EXPORT_CSS", "CSS"])
def test_result_css_passes_the_design_lint(name):
    assert css_lint(getattr(report, name)) == []


def test_verdict_colours_use_the_new_tokens():
    assert report.VERDICT_COLOR["VERIFY"] == "var(--verify)"
    assert set(report.VERDICT_COLOR) == {"VERIFY", "PREFER", "CONDITIONAL", "AVOID",
                                         "NOT ASSESSED"}
    assert report.INERT == "var(--muted)"


def test_band_bar_follows_configured_bands():
    a = clean()
    default = report._band_bar(a, None)
    assert default.count("rt-band__seg ") == 3
    assert "width:60%" in default and default.count("width:20%") == 2
    assert 'role="img"' in default and "AVOID 0 to 60, CONDITIONAL 60 to 80, PREFER 80 to 100" in default
    custom = report._band_bar(a, [(85, "PREFER"), (65, "CONDITIONAL"), (0, "AVOID")])
    assert "width:65%" in custom and "AVOID 0 to 65" in custom
    assert 'left:88%' in custom


def test_the_calculation_summary_sits_beside_the_exposure_card():
    a = clean()
    a.exposure_min = a.exposure_max = 58.3
    markup = block(a, [][:0] or None, [])
    assert markup.index(EXPOSURE) < markup.index("Applied scoring inputs")
    assert markup.count("<h3>Applied scoring inputs</h3>") == 1


def test_stub_evidenceview_degrades_instead_of_failing(monkeypatch):
    def stub(rows, view):
        raise NotImplementedError
    monkeypatch.setattr(evidenceview, "evidence_card", stub)
    assert "Vulnerabilities to review" in block(verify(), None, [finding()])
