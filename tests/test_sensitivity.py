"""Tests for weight configuration, sensitivity analysis and snapshots."""

import json

import pytest

from retrust import config, score, sensitivity, snapshot
from retrust.match import Finding


def _finding(cvss=7.5, epss=0.01, kev=False, remediation="vendor_fix"):
    return Finding(cve="CVE-2026-0001", advisory_id="ICSA-26-001-01", cvss=cvss,
                   cwe="CWE-79", epss=epss, in_kev=kev, ransomware=False,
                   version_range="vers:all/*", decided=True, remediation=remediation)


# --- config ----------------------------------------------------------------

def test_defaults_when_no_file(tmp_path):
    weights, bands, source = config.load(tmp_path / "absent.json")
    assert weights == score.DEFAULT_WEIGHTS
    assert source == "built-in defaults"
    assert bands == list(score.BANDS)


def test_custom_weights_are_read(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"weights": {"exploitation": 1.0, "severity": 1.0}}))
    weights, _, source = config.load(path)
    assert weights == {"exploitation": 1.0, "severity": 1.0}
    assert str(path) in source


def test_unknown_pillar_is_rejected(tmp_path):
    """A typo must fail loudly rather than silently scoring on fewer pillars."""
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"weights": {"explotation": 1.0}}))
    with pytest.raises(SystemExit, match="unknown pillar"):
        config.load(path)


def test_inverted_bands_are_rejected(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"bands": {"prefer": 40, "conditional": 70}}))
    with pytest.raises(SystemExit, match="inverted"):
        config.load(path)


def test_all_zero_weights_rejected(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"weights": {"exploitation": 0, "severity": 0}}))
    with pytest.raises(SystemExit, match="must not all be zero"):
        config.load(path)


def test_template_round_trips(tmp_path):
    written = config.write_template(tmp_path / "c.json")
    weights, bands, _ = config.load(written)
    assert weights == score.DEFAULT_WEIGHTS
    with pytest.raises(SystemExit, match="already exists"):
        config.write_template(written)


def test_custom_bands_change_the_verdict():
    """The same evidence yields different verdicts under different policies."""
    findings = [_finding(cvss=5.0, epss=0.001)]
    baseline = score.assess("x", findings).score

    lenient = [(10, "PREFER"), (5, "CONDITIONAL"), (0, "AVOID")]
    strict = [(baseline + 5, "PREFER"), (baseline + 2, "CONDITIONAL"), (0, "AVOID")]
    assert score.assess("x", findings, bands=lenient).verdict == "PREFER"
    assert score.assess("x", findings, bands=strict).verdict == "AVOID"


# --- severity must discriminate --------------------------------------------

def test_severity_distinguishes_products():
    """The bug this guards: peak-CVSS-only scored ~0 for every OT product.

    Nearly everything in this corpus has a 9.8, so "100 - peak * 10" made the
    pillar a flat penalty that ranked nothing against anything.
    """
    one_critical = [_finding(cvss=9.8)] + [_finding(cvss=4.0) for _ in range(19)]
    mostly_critical = [_finding(cvss=9.8) for _ in range(16)] + \
                      [_finding(cvss=4.0) for _ in range(4)]
    assert score._severity(one_critical).score > score._severity(mostly_critical).score
    assert score._severity(one_critical).score > 5    # not pinned to the floor


def test_severity_still_punishes_the_worst_case():
    assert score._severity([_finding(cvss=10.0)]).score < \
           score._severity([_finding(cvss=5.0)]).score


# --- sensitivity -----------------------------------------------------------

def test_clear_cut_product_is_robust():
    """A product bad on every pillar must not depend on the weighting.

    Critical, likely exploited and unfixable is a hard gate, so the weighting
    cannot rescue it. Before that gate existed this case reached AVOID under
    only 41% of weightings, because pillars the vendor scored well on offset
    the one that made the product unbuyable.
    """
    findings = [_finding(cvss=10.0, epss=0.9, remediation="none_available")
                for _ in range(5)]
    result = sensitivity.stability(findings, {"A"}, samples=200)
    assert result.gated
    assert result.robust
    assert result.dominant == "AVOID"


def test_unfixable_critical_is_a_gate():
    unfixable = [_finding(cvss=9.8, epss=0.8, remediation="none_available")]
    fixable = [_finding(cvss=9.8, epss=0.8, remediation="vendor_fix")]
    assert score.assess("x", unfixable, {"A"}).verdict == "AVOID"
    assert any("no available fix" in g["gate"]
               for g in score.assess("x", unfixable, {"A"}).gates)
    # The same flaw with a fix available is not gated.
    assert not any("no available fix" in g["gate"]
                   for g in score.assess("x", fixable, {"A"}).gates)


def test_vendor_practice_discriminates_on_csaf_publishing():
    """The bug this guards: the pillar returned ~100 for every vendor.

    Advisory content quality is near-constant because CISA normalises what it
    republishes, so it added free points everywhere. Running your own CSAF feed
    is the part that actually varies between vendors.
    """
    findings = [_finding()]
    publisher = score._vendor_practice(findings, {"A"}, vendor_key="siemens")
    other = score._vendor_practice(findings, {"A"}, vendor_key="someoneelse")
    assert publisher.score > other.score
    assert any("own CSAF" in e for e in publisher.evidence)
    assert any("relies on CISA" in e for e in other.evidence)


def test_gated_product_skips_sampling():
    """A hard gate decides outright, so reporting a sampled agreement would lie."""
    findings = [_finding(kev=True)]
    result = sensitivity.stability(findings, {"A"}, samples=200)
    assert result.gated
    assert result.samples == 0
    assert "weighting is irrelevant" in result.summary()


def test_sampling_is_reproducible():
    findings = [_finding(cvss=8.0, epss=0.05)]
    first = sensitivity.stability(findings, {"A"}, samples=100, seed=42)
    second = sensitivity.stability(findings, {"A"}, samples=100, seed=42)
    assert first.verdicts == second.verdicts
    assert first.score_median == second.score_median


def test_different_seeds_still_agree_on_a_clear_case():
    findings = [_finding(cvss=2.0, epss=0.0001, remediation="vendor_fix")]
    verdicts = {sensitivity.stability(findings, {"A"}, samples=200, seed=s).dominant
                for s in (1, 7, 99)}
    assert len(verdicts) == 1


def test_dominance_prefers_the_better_candidate():
    good = ([_finding(cvss=4.0, epss=0.001)], {"A"}, (), ())
    bad = ([_finding(cvss=9.9, epss=0.8, remediation="none_available")], {"B"}, (), ())
    assert sensitivity.dominance(good, bad, samples=200) > 0.9
    assert sensitivity.dominance(bad, good, samples=200) < 0.1


def test_dominance_respects_gates():
    clean = ([_finding(cvss=9.9, epss=0.5)], {"A"}, (), ())
    gated = ([_finding()], {"B"}, (), ({"gate": "g", "detail": "d", "source": "s"},))
    assert sensitivity.dominance(clean, gated, samples=100) == 1.0


def test_contributions_sum_to_the_score():
    findings = [_finding(cvss=7.0, epss=0.02)]
    assessment = score.assess("x", findings, {"A"})
    rows = sensitivity.contributions(assessment)
    assert sum(r["points"] for r in rows) == pytest.approx(assessment.score, abs=0.2)
    # Ordered by how many points each pillar cost, so the worst is first.
    assert rows == sorted(rows, key=lambda r: -r["points_lost"])


def test_contributions_exclude_evidence_quality():
    assessment = score.assess("x", [_finding()], {"A"})
    assert "Evidence quality" not in [r["pillar"] for r in sensitivity.contributions(assessment)]


# --- snapshot --------------------------------------------------------------

@pytest.fixture
def data_dir(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / "retrust.db").write_bytes(b"SQLite format 3\x00" + b"x" * 500)
    (directory / "certifications.json").write_text("[]")
    (directory / "screening.json").write_text("[]")
    return directory


def test_snapshot_round_trip(data_dir, tmp_path):
    out = tmp_path / "snap.zip"
    created = snapshot.create(data_dir, out, provenance=[
        {"source": "CISA KEV", "detail": "1,726 entries", "captured": "2026-09-27"}])
    assert len(created["files"]) == 3

    target = tmp_path / "restored"
    result = snapshot.restore(out, target)
    assert sorted(result["restored"]) == sorted(snapshot.CONTENTS)
    assert (target / "retrust.db").read_bytes().startswith(b"SQLite format 3")
    assert result["provenance"][0]["source"] == "CISA KEV"


def test_snapshot_detects_tampering(data_dir, tmp_path):
    """A result is only reproducible if the data is provably unchanged."""
    import zipfile
    out = tmp_path / "snap.zip"
    snapshot.create(data_dir, out)

    tampered = tmp_path / "bad.zip"
    with zipfile.ZipFile(out) as src, zipfile.ZipFile(tampered, "w") as dst:
        for name in src.namelist():
            payload = src.read(name)
            if name == "certifications.json":
                payload += b" "          # one byte
            dst.writestr(name, payload)

    with pytest.raises(SystemExit, match="checksum mismatch"):
        snapshot.restore(tampered, tmp_path / "out")


def test_snapshot_requires_an_index(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(SystemExit, match="No index"):
        snapshot.create(empty, tmp_path / "s.zip")


def test_snapshot_rejects_a_future_format(data_dir, tmp_path):
    import zipfile
    out = tmp_path / "snap.zip"
    snapshot.create(data_dir, out)
    manifest = snapshot.inspect(out)
    manifest["format"] = 99

    future = tmp_path / "future.zip"
    with zipfile.ZipFile(out) as src, zipfile.ZipFile(future, "w") as dst:
        for name in src.namelist():
            dst.writestr(name, json.dumps(manifest) if name == snapshot.MANIFEST
                         else src.read(name))

    with pytest.raises(SystemExit, match="not supported"):
        snapshot.restore(future, tmp_path / "out")
