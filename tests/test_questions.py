"""Tests for the RFQ security annex.

The failure mode worth guarding against is a question the evidence does not
support: one invented ask teaches the vendor that the whole annex is
boilerplate. So beside checking that each generator fires on its trigger,
these tests check that it stays silent without one -- a fixed KEV finding, a
certified vendor, a profile that was never built.
"""

from retrust import dossier, questions, score
from retrust.match import Finding

WORMABLE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H"

KEV_GATE = {"gate": "Known exploited vulnerability",
            "detail": "1 CVE(s) appear in CISA's KEV catalogue: CVE-2026-0001",
            "source": "CISA Known Exploited Vulnerabilities catalogue"}


def _finding(cve="CVE-2026-0001", **overrides):
    base = dict(cve=cve, advisory_id="ICSA-26-001-01", cvss=9.8, cwe="CWE-787",
                epss=0.5, in_kev=False, ransomware=False,
                version_range="vers:intdot/<2.0", decided=True,
                remediation="vendor_fix", vector=None)
    base.update(overrides)
    return Finding(**base)


def _assessment(findings=(), **overrides):
    base = dict(product="TestPLC 9000", verdict="CONDITIONAL", score=55.0,
                findings_count=len({f.cve for f in findings}),
                undecided_count=sum(1 for f in findings if not f.decided))
    base.update(overrides)
    return score.Assessment(**base)


# --- the evidence-driven generators ----------------------------------------

def test_a_kev_finding_without_a_fix_demands_a_version_and_a_date():
    finding = _finding(in_kev=True, remediation="none_available")
    built = questions.build(_assessment([finding], gates=[KEV_GATE]), [finding])
    kev = built[0]
    assert "CVE-2026-0001" in kev.evidence
    assert "version" in kev.text and "date" in kev.text
    # The verdict's own gate is quoted, so annex and score share the evidence.
    assert any("Known exploited" in fact for fact in kev.evidence)


def test_a_kev_finding_the_vendor_fixed_raises_no_kev_question():
    """Demanding a fix that already shipped would be the boilerplate to avoid."""
    finding = _finding(in_kev=True, remediation="vendor_fix")
    built = questions.build(_assessment([finding]), [finding])
    assert all("KEV" not in question.why for question in built)
    # Structural, not prose-keyed: no question cites the fixed CVE at all, so
    # a rewording of the why can never make this pass vacuously.
    assert not any(finding.cve in question.evidence for question in built)


def test_ransomware_flagged_kev_findings_are_named_separately():
    used = _finding("CVE-2026-0001", in_kev=True, ransomware=True,
                    remediation="mitigation")
    plain = _finding("CVE-2026-0002", in_kev=True, remediation="mitigation")
    built = questions.build(_assessment([used, plain]), [used, plain])
    assert "ransomware" in built[0].why
    assert "CVE-2026-0001" in built[0].evidence
    assert "CVE-2026-0002" not in built[0].evidence
    assert "CVE-2026-0002" in built[1].evidence


def test_the_roadmap_question_cites_in_epss_order_not_cve_order():
    """The elision must drop the least likely CVE, never the most."""
    low = _finding("CVE-2026-0001", remediation="none_available", epss=0.05)
    high = _finding("CVE-2026-0009", remediation="none_available", epss=0.9)
    mid = _finding("CVE-2026-0005", remediation="unknown", epss=0.4)
    findings = [low, high, mid]
    built = questions.build(_assessment(findings), findings)
    assert built[0].evidence == ["CVE-2026-0009", "CVE-2026-0005",
                                 "CVE-2026-0001"]


def test_cited_ids_are_capped_at_six_with_the_rest_counted():
    findings = [_finding(f"CVE-2026-{n:04}", remediation="none_available",
                         epss=0.9 - n / 100) for n in range(1, 9)]
    roadmap = questions.build(_assessment(findings), findings)[0]
    assert sum(1 for e in roadmap.evidence if e.startswith("CVE-")) == 6
    assert roadmap.evidence[-1] == "and 2 more"


def test_a_mitigation_only_finding_needs_epss_above_the_threshold():
    """At 0.1 exactly, "is a fix planned" is diligence, not a cited urgency."""
    calm = _finding(remediation="workaround", epss=0.1)
    built = questions.build(_assessment([calm]), [calm])
    assert all("survives" not in question.text for question in built)

    pressing = _finding(remediation="mitigation", epss=0.2)
    built = questions.build(_assessment([pressing]), [pressing])
    assert any("survives a firmware update" in question.text
               for question in built)


def test_an_unmeasured_epss_does_not_count_as_pressing():
    unmeasured = _finding(remediation="workaround", epss=None)
    built = questions.build(_assessment([unmeasured]), [unmeasured])
    assert all("survives" not in question.text for question in built)


def test_undecided_ranges_ask_the_vendor_to_confirm_citing_advisories():
    findings = [_finding("CVE-2026-0001", advisory_id="ICSA-26-002-01",
                         decided=False),
                _finding("CVE-2026-0002", advisory_id="ICSA-26-003-02",
                         decided=False)]
    built = questions.build(_assessment(findings), findings)
    confirm = next(q for q in built if "quoting" in q.text)
    assert confirm.evidence == ["ICSA-26-002-01", "ICSA-26-003-02"]
    assert "2 finding(s)" in confirm.why


def test_wormable_vectors_prompt_the_secure_by_default_question():
    spreading = _finding(vector=WORMABLE)
    built = questions.build(_assessment([spreading]), [spreading])
    hardening = next(q for q in built if "default" in q.text)
    assert "CVE-2026-0001" in hardening.evidence


def test_a_local_or_absent_vector_prompts_no_hardening_question():
    """cvss.parse(None) is None, and None must contribute nothing."""
    findings = [_finding("CVE-2026-0001", vector=LOCAL),
                _finding("CVE-2026-0002", vector=None)]
    built = questions.build(_assessment(findings), findings)
    assert all("default" not in question.text for question in built)


# --- the profile-derived questions -----------------------------------------

def test_no_profile_means_no_profile_questions():
    built = questions.build(_assessment(), [], profile=None)
    text = " ".join(question.text for question in built)
    assert "62443" not in text
    assert "notified" not in text


def test_a_certified_self_publishing_vendor_is_not_asked_to_prove_it():
    profile = dossier.Dossier(vendor="Testco", vendor_key="testco",
                              certificates=[{"scheme": "ISASecure"}],
                              csaf_feed="https://example.test/csaf.json")
    built = questions.build(_assessment(), [], profile=profile)
    text = " ".join(question.text for question in built)
    assert "62443" not in text
    assert "notified" not in text


def test_an_uncertified_vendor_without_a_feed_is_asked_about_both():
    profile = dossier.Dossier(vendor="Testco", vendor_key="testco",
                              certificates=[])
    built = questions.build(_assessment(), [], profile=profile)
    text = " ".join(question.text for question in built)
    assert "62443" in text
    assert "machine-readable" in text


def test_an_unloaded_certificate_cache_is_not_claimed_as_a_gap():
    """"Not checked" and "nothing found" must give different reasons."""
    unchecked = dossier.Dossier(vendor="Testco", vendor_key="testco")
    asked = next(q for q in questions.build(_assessment(), [], profile=unchecked)
                 if "62443" in q.text)
    assert "could not check" in asked.why

    measured = dossier.Dossier(vendor="Testco", vendor_key="testco",
                               certificates=[])
    asked = next(q for q in questions.build(_assessment(), [], profile=measured)
                 if "62443" in q.text)
    assert "No ISASecure or Common Criteria entry" in asked.why


# --- the cap and the standing block ----------------------------------------

def _everything():
    """One of each trigger, so every generator fires at once."""
    findings = [
        _finding("CVE-2026-0001", in_kev=True, ransomware=True,
                 remediation="none_available", epss=0.9),
        _finding("CVE-2026-0002", in_kev=True, remediation="mitigation"),
        _finding("CVE-2026-0003", remediation="none_available", epss=0.4),
        _finding("CVE-2026-0004", remediation="workaround", epss=0.3),
        _finding("CVE-2026-0005", decided=False),
        _finding("CVE-2026-0006", vector=WORMABLE),
    ]
    profile = dossier.Dossier(vendor="Testco", vendor_key="testco",
                              certificates=[])
    return _assessment(findings, gates=[KEV_GATE]), findings, profile


def test_the_total_is_capped_and_the_standing_block_survives():
    built = questions.build(*_everything())
    assert len(built) <= questions.MAX_QUESTIONS
    tail = " ".join(question.text for question in built[-3:])
    assert "SBOM" in tail and "end-of-life" in tail and "PSIRT" in tail


def test_zero_findings_still_asks_the_standing_block_and_owns_the_silence():
    built = questions.build(_assessment(), [])
    text = " ".join(question.text for question in built)
    assert "SBOM" in text and "end-of-life" in text and "PSIRT" in text
    whys = " ".join(question.why for question in built)
    assert "not evidence of safety" in whys


def test_a_cve_is_not_asked_about_twice_across_generators():
    """A KEV CVE with no fix gets the sharper demand, not that plus a repeat."""
    finding = _finding(in_kev=True, remediation="none_available")
    built = questions.build(_assessment([finding]), [finding])
    citing = [q for q in built if "CVE-2026-0001" in q.evidence]
    assert len(citing) == 1


# --- the printed annex ------------------------------------------------------

def test_format_report_numbers_the_questions_and_shows_each_why():
    built = questions.build(*_everything())
    text = questions.format_report("TestPLC 9000", built)
    lines = text.splitlines()
    assert lines[0].startswith("RFQ SECURITY ANNEX")
    for number in range(1, len(built) + 1):
        assert any(line.startswith(f"{number:>2}. ") for line in lines), number
    assert text.count("why:") == len(built)


def test_format_report_closes_with_questions_not_accusations():
    built = questions.build(_assessment(), [])
    text = questions.format_report("TestPLC 9000", built)
    assert "questions, not accusations" in text
    assert "diligent discloser" in text


def test_format_report_stays_ascii_and_inside_eighty_columns():
    """The annex must survive NO_COLOR, pipes and a procurement Word file."""
    text = questions.format_report("TestPLC 9000", questions.build(*_everything()))
    assert text.isascii()
    assert all(len(line) <= 80 for line in text.splitlines())


def test_the_same_input_twice_prints_the_same_annex():
    first = questions.format_report("TestPLC 9000", questions.build(*_everything()))
    second = questions.format_report("TestPLC 9000", questions.build(*_everything()))
    assert first == second


def test_an_unresolved_product_never_claims_a_clean_history():
    """NOT ASSESSED means the resolver abstained: a different fact from "no
    advisory names it", and the annex must not conflate the two."""
    assessment = score.not_assessed("Siemems Mystery PLC", "vendor unknown")
    built = questions.build(assessment, [])
    accounted = [q for q in built if "could not resolve" in q.why]
    assert len(accounted) == 1
    assert all("No advisory in this index" not in q.why for q in built)


def test_a_novel_length_product_name_stays_inside_the_header():
    text = questions.format_report("X" * 330, questions.build(_assessment(), []))
    assert max(len(line) for line in text.splitlines()) <= 80
    assert text.isascii()
