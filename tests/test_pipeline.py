"""Tests for ingest, matching and scoring, using a small hand-built advisory.

These run without the real corpus so they stay fast and deterministic.
"""

import json

import pytest

from retrust import csaf, index, match, score

ADVISORY = {
    "document": {
        "title": "Test PLC vulnerabilities",
        "tracking": {"id": "ICSA-26-001-01", "initial_release_date": "2026-01-01T00:00:00Z"},
    },
    "product_tree": {
        "branches": [{
            "category": "vendor", "name": "Testco Electric",
            "branches": [{
                "category": "product_name", "name": "TestPLC 9000 (TC-9000-A1)",
                "branches": [
                    {"category": "product_version_range", "name": "vers:intdot/<2.0",
                     "product": {"product_id": "P1", "name": "TestPLC 9000 < 2.0",
                                 "product_identification_helper": {"model_numbers": ["TC-9000-A1"]}}},
                    {"category": "product_version_range", "name": ">=2.0|<3.0",
                     "product": {"product_id": "P2", "name": "TestPLC 9000 2.x"}},
                ],
            }],
        }],
    },
    "vulnerabilities": [
        {"cve": "CVE-2026-0001", "cwe": {"id": "CWE-79"},
         "product_status": {"known_affected": ["P1"]},
         "scores": [{"cvss_v3": {"baseScore": 9.8}, "products": ["P1"]}]},
        {"cve": "CVE-2026-0002", "cwe": {"id": "CWE-22"},
         "product_status": {"known_affected": ["P1", "P2"]},
         "scores": [{"cvss_v3": {"baseScore": 5.3}, "products": ["P1", "P2"]}]},
    ],
}


@pytest.fixture
def db(tmp_path):
    advisory_dir = tmp_path / "csaf"
    advisory_dir.mkdir()
    (advisory_dir / "icsa-26-001-01.json").write_text(json.dumps(ADVISORY))
    connection, _ = index.build(str(tmp_path / "t.db"), str(advisory_dir))
    with connection:
        connection.execute(
            "INSERT INTO exploitation (cve, epss, in_kev, ransomware) VALUES (?,?,?,?)",
            ("CVE-2026-0001", 0.87, 1, 1))
    return connection


def test_ingest_reads_products_and_cves(db):
    stats = index.stats(db)
    assert stats["advisories"] == 1
    assert stats["products"] == 2
    assert stats["cves"] == 2


def test_order_number_is_extracted_from_the_name():
    assert "TC-9000-A1" in csaf.find_order_numbers("TestPLC 9000 (TC-9000-A1)")


def test_ratings_are_not_mistaken_for_order_numbers():
    """A wrong order-number match is worse than none, so these must be rejected."""
    for text in ["Power supply (54VDC)", "Module (2 GB)", "Widget (V2.1)"]:
        assert csaf.find_order_numbers(text) == set()


def test_vendor_spellings_collapse():
    assert index.normalize_vendor("Testco Electric") == index.normalize_vendor("Testco")
    assert index.normalize_vendor("Johnson Controls, Inc.") == index.normalize_vendor(
        "Johnson Controls Inc")


def test_resolve_by_order_number(db):
    resolution = match.resolve(db, order_number="tc9000a1")
    assert resolution.resolved
    assert resolution.method == "order_number"
    assert resolution.confidence >= 0.95


def test_resolve_by_vendor_and_name(db):
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    assert resolution.resolved
    assert len(resolution.matches) == 2       # both version branches of the family


def test_abstains_on_unknown_vendor(db):
    resolution = match.resolve(db, vendor="Nobody Ltd", product="Whatever")
    assert not resolution.resolved
    assert "does not appear" in resolution.reason


def test_abstains_on_unknown_product(db):
    resolution = match.resolve(db, vendor="Testco", product="zzzz not a product")
    assert not resolution.resolved


def test_version_filter_excludes_unaffected(db):
    """Firmware 2.5 is outside "<2.0", so CVE-2026-0001 must drop out."""
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    cves = {f.cve for f in match.findings(db, resolution, version="2.5")}
    assert "CVE-2026-0001" not in cves
    assert "CVE-2026-0002" in cves


def test_version_filter_includes_affected(db):
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    cves = {f.cve for f in match.findings(db, resolution, version="1.9")}
    assert "CVE-2026-0001" in cves


def test_kev_is_a_hard_gate(db):
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    findings = match.findings(db, resolution, version="1.9")
    assessment = score.assess("TestPLC 9000", findings, {"ICSA-26-001-01"})
    assert assessment.verdict == "AVOID"
    assert any("Known exploited" in g["gate"] for g in assessment.gates)


def test_gate_cannot_be_averaged_away(db):
    """Even with otherwise strong pillars, a gate still forces AVOID."""
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    findings = match.findings(db, resolution, version="1.9")
    assessment = score.assess("TestPLC 9000", findings, {"ICSA-26-001-01"},
                              weights={"exploitation": 0.01, "severity": 0.01,
                                       "vendor_practice": 0.98})
    assert assessment.verdict == "AVOID"


def test_clean_product_scores_well(db):
    """Version 2.5 avoids the KEV CVE and should not be gated."""
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    findings = match.findings(db, resolution, version="2.5")
    assessment = score.assess("TestPLC 9000", findings, {"ICSA-26-001-01"})
    assert assessment.gates == []
    assert assessment.verdict in ("PREFER", "CONDITIONAL")


def test_evidence_quality_is_not_in_the_score(db):
    """Confidence must not inflate the risk score, whatever the weights are."""
    resolution = match.resolve(db, vendor="Testco", product="TestPLC 9000")
    findings = match.findings(db, resolution, version="2.5")
    assessment = score.assess("TestPLC 9000", findings, {"ICSA-26-001-01"})

    weights = score.DEFAULT_WEIGHTS
    keys = {spec.name: spec.key for spec in score.PILLARS}
    risk = [p for p in assessment.pillars
            if p.name != "Evidence quality" and p.scored]
    # Only pillars that measured something participate; the rest are excluded
    # and the remaining exponents renormalized -- one rule for every pillar.
    # The composite is a PRODUCT of pillar ** exponent, not a mean.
    total = sum(weights[keys[p.name]] for p in risk)
    expected = 1.0
    for pillar in risk:
        expected *= max(pillar.score, score.FLOOR) ** (weights[keys[pillar.name]] / total)
    assert assessment.score == pytest.approx(expected, abs=0.1)

    # Evidence quality is present in the output but carries no weight key.
    assert any(p.name == "Evidence quality" for p in assessment.pillars)
    assert "evidence_quality" not in score.DEFAULT_WEIGHTS


# --- robustness against bad input ------------------------------------------

MALFORMED = {
    "not-json.json": "{ this is not json",
    "null-document.json": '{"document": null}',
    "top-level-list.json": "[1, 2, 3]",
    "null-tree.json": '{"document": {}, "product_tree": null}',
    "null-vuln.json": '{"document":{},"product_tree":{"branches":[]},"vulnerabilities":[null]}',
    "empty.json": "",
    "binary.json": "\x00\x01\x02",
    "wrong-types.json": '{"document": {"tracking": 7}, "product_tree": {"branches": "x"}}',
}


def test_one_bad_advisory_does_not_abort_the_ingest(tmp_path):
    """The corpus is ~4,000 files from hundreds of vendors.

    One of them having "document": null must not cost us the other 3,936.
    """
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "good.json").write_text(json.dumps(ADVISORY))
    for name, payload in MALFORMED.items():
        (directory / name).write_text(payload)

    connection, counts = index.build(str(tmp_path / "t.db"), str(directory))
    assert counts["advisories"] == 1          # the good one still landed
    assert index.stats(connection)["cves"] == 2


@pytest.mark.parametrize("payload", list(MALFORMED.values()))
def test_parse_returns_none_rather_than_raising(tmp_path, payload):
    path = tmp_path / "a.json"
    path.write_text(payload)
    assert csaf.parse(path) is None


def test_parse_handles_a_missing_file(tmp_path):
    assert csaf.parse(tmp_path / "absent.json") is None


def test_epss_loads_with_or_without_the_comment_line(tmp_path):
    """The bug this guards: blindly skipping line 1 to drop EPSS's comment.

    Not every mirror ships the "#model_version" line. When it was absent the
    skip ate the CSV header instead and the load died with KeyError: 'cve',
    which took the exploitation signals with it.
    """
    for label, text in [
            ("with comment", "#model_version:v1\ncve,epss,percentile\nCVE-2026-0001,0.5,0.9\n"),
            ("without comment", "cve,epss,percentile\nCVE-2026-0001,0.5,0.9\n")]:
        path = tmp_path / f"{label}.csv"
        path.write_text(text)
        connection = index.connect(str(tmp_path / f"{label}.db"))
        with connection:
            # Columns named, not positional: this row only needs a CVE to
            # exist, and a positional insert breaks every time the schema grows
            # a field this test does not care about.
            connection.execute(
                "INSERT INTO affected (advisory_id, product_id, cve, cvss, cwe,"
                " remediation) VALUES"
                " ('A','P','CVE-2026-0001',7.0,'CWE-1','vendor_fix')")
        assert index.load_exploitation(connection, epss_path=str(path))["epss"] == 1, label


# --- the resolution ladder must not cross identities ------------------------

def test_a_numeric_prefix_is_not_extended_by_more_digits(tmp_path):
    """RSLogix 5 matched RSLogix 500 and RSLogix 5000.

    Normalisation strips the punctuation that separated the components, so a
    plain prefix test crossed into three different products with three different
    advisory sets.
    """
    from retrust import match
    key = match.boundary_key
    assert match.prefix_matches(key("RSLogix 5"), key("RSLogix 5"))
    assert not match.prefix_matches(key("RSLogix 5"), key("RSLogix 500"))
    assert not match.prefix_matches(key("RSLogix 5"), key("RSLogix 5000"))
    # A real family member continues at a separator, and must survive. The
    # first of these is why the check cannot simply refuse a following digit:
    # normalisation had already eaten the hyphen in "1518-4".
    assert match.prefix_matches(key("SIMATIC S7-1500 CPU 1518"),
                                 key("SIMATIC S7-1500 CPU 1518-4 PN/DP MFP"))
    assert match.prefix_matches(key("RSLogix 5"), key("RSLogix 5 FactoryTalk"))
    assert match.prefix_matches(key("SIMATIC S7-1500"), key("SIMATIC S7-1500 CPU"))


def test_an_order_number_naming_two_vendors_abstains(tmp_path):
    """Merging them scored one product against another company's advisories."""
    from retrust import index, match
    directory = tmp_path / "csaf"
    directory.mkdir()
    for n, vendor in enumerate(("Ecava", "Intellicom")):
        (directory / f"a{n}.json").write_text(json.dumps({
            "document": {"title": "T", "tracking": {"id": f"ICSA-26-00{n}-01"}},
            "product_tree": {"branches": [{
                "category": "vendor", "name": vendor, "branches": [{
                    "category": "product_name", "name": f"Box {n} (EC150)",
                    "branches": [{"category": "product_version", "name": "1.0",
                                  "product": {"product_id": "P1", "name": "Box"}}]}]}]},
            "vulnerabilities": [],
        }))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    resolution = match.resolve(connection, order_number="EC150")
    assert resolution.abstained
    assert "2 manufacturers" in resolution.reason
    assert "Ecava" in resolution.reason and "Intellicom" in resolution.reason
    # Naming the vendor resolves it.
    assert match.resolve(connection, vendor="Ecava", order_number="EC150").resolved


def test_a_snapshot_naming_a_path_is_refused(tmp_path):
    """A manifest travels inside the archive, so its names are untrusted."""
    import json
    import zipfile

    import pytest

    from retrust import snapshot

    bundle_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(bundle_path, "w") as bundle:
        bundle.writestr("retrust.db", b"x")
        bundle.writestr(snapshot.MANIFEST, json.dumps({
            "format": snapshot.FORMAT_VERSION,
            "files": {"../escape.txt": {"sha256": "0" * 64, "bytes": 1}}}))
    with pytest.raises(SystemExit, match="not a file a ReTrust snapshot"):
        snapshot.restore(str(bundle_path), data_dir=str(tmp_path / "data"))
    assert not (tmp_path / "escape.txt").exists()
