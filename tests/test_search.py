"""Search has to be trustworthy in two directions.

A hit must be a thing the corpus really holds, with the rung that found it
named honestly, and a miss must be reported as a miss. These tests therefore
check the counts against the index itself rather than against constants, and
they check just as hard that a hopeless query returns nothing at all: a "did you
mean" that invents a plausible vendor is worse than one that stays quiet.
"""

import json

import pytest

from retrust import index, search


# --- the fixture corpus ------------------------------------------------------

def leaf(product_id, name, model=None):
    product = {"product_id": product_id, "name": name}
    if model:
        product["product_identification_helper"] = {"model_numbers": [model]}
    return {"category": "product_version_range", "name": "vers:intdot/<2.0",
            "product": product}


def branch(name, *leaves):
    return {"category": "product_name", "name": name, "branches": list(leaves)}


def vendor(name, *branches):
    return {"category": "vendor", "name": name, "branches": list(branches)}


def advisory(advisory_id, released, branches, affected):
    return {
        "document": {"title": advisory_id,
                     "tracking": {"id": advisory_id,
                                  "initial_release_date": released}},
        "product_tree": {"branches": branches},
        "vulnerabilities": [{"cve": f"CVE-2026-{advisory_id[-2:]}01",
                             "product_status": {"known_affected": affected}}],
    }


# Two advisories that between them cover every case the module has to handle:
# one product named by both of them, two vendors sharing a product name, and the
# Siemens/Simens pair that the similarity tie-break exists for.
ONE = advisory("ICSA-26-001-01", "2026-01-01T00:00:00Z", [
    vendor("Testco Electric",
           branch("TestPLC 9000 (TC-9000-A1)", leaf("P1", "TestPLC 9000", "TC-9000-A1")),
           branch("TestPLC 9000 Panel", leaf("P2", "TestPLC 9000 Panel"))),
    vendor("Testco Partners Group",
           branch("Gateway 10", leaf("P3", "Gateway 10")),
           branch("Widgetron 500", leaf("P4", "Widgetron 500", "WG-500-X"))),
    vendor("Siemens", branch("SIMATIC S7-1500", leaf("P5", "SIMATIC S7-1500"))),
], ["P1", "P2", "P3", "P4", "P5"])

TWO = advisory("ICSA-26-002-01", "2026-02-01T00:00:00Z", [
    vendor("Testco Electric",
           branch("TestPLC 9000 (TC-9000-A1)", leaf("Q1", "TestPLC 9000", "TC-9000-A1"))),
    vendor("Other Industries", branch("Widgetron 500", leaf("Q2", "Widgetron 500"))),
    vendor("Siemens", branch("SIMATIC S7-1500", leaf("Q3", "SIMATIC S7-1500"))),
    vendor("Simens", branch("SIMATIC S7-1200", leaf("Q4", "SIMATIC S7-1200"))),
], ["Q1", "Q2", "Q3", "Q4"])


@pytest.fixture
def db(tmp_path):
    directory = tmp_path / "csaf"
    directory.mkdir()
    (directory / "one.json").write_text(json.dumps(ONE))
    (directory / "two.json").write_text(json.dumps(TWO))
    connection, _ = index.build(str(tmp_path / "t.db"), str(directory))
    return connection


@pytest.fixture
def empty(tmp_path):
    return index.connect(str(tmp_path / "empty.db"))


# --- vendors -----------------------------------------------------------------

def test_vendors_finds_an_exact_normalised_match(db):
    hits = search.vendors(db, "Testco Electric")
    assert hits[0].method == "exact"
    assert hits[0].vendor == "Testco Electric"
    assert (hits[0].products, hits[0].advisories) == (3, 2)


def test_vendors_counts_come_from_the_corpus(db):
    """No number here may be computed anywhere but in the index."""
    for hit in search.vendors(db, "Testco"):
        key = index.normalize_vendor(hit.vendor)
        row = db.execute(
            "SELECT COUNT(*) p, COUNT(DISTINCT advisory_id) a FROM product"
            " WHERE vendor_key = ?", (key,)).fetchone()
        assert (hit.products, hit.advisories) == (row["p"], row["a"])


def test_vendors_ranks_stronger_rungs_first(db):
    assert [hit.method for hit in search.vendors(db, "Testco")] == ["exact", "prefix"]


def test_vendors_ignores_the_entries_with_no_vendor_at_all(db):
    """A blank vendor is not an answer about anything, so it never ranks."""
    assert all(hit.vendor for hit in search.vendors(db, "Testco"))


# --- products ----------------------------------------------------------------

def test_products_groups_the_same_product_across_advisories(db):
    """Two advisories name this product, so it is one row that counts them."""
    name = "TestPLC 9000 (TC-9000-A1)"
    hits = [hit for hit in search.products(db, name) if hit.name == name]
    assert len(hits) == 1
    assert hits[0].advisories == 2
    assert db.execute("SELECT COUNT(*) FROM product WHERE name_key = ?",
                      (index.normalize_name(name),)).fetchone()[0] == 2


def test_products_reports_the_order_numbers(db):
    hit = search.products(db, "TestPLC 9000 (TC-9000-A1)")[0]
    assert hit.order_numbers == ("9000-A1", "TC-9000-A1")


def test_products_do_not_inherit_another_vendors_order_number(db):
    """Two vendors name a Widgetron 500; only one of them gives a number."""
    by_vendor = {hit.vendor: hit for hit in search.products(db, "Widgetron 500")}
    assert by_vendor["Testco Partners Group"].order_numbers == ("WG-500-X",)
    assert by_vendor["Other Industries"].order_numbers == ()


def test_products_reports_which_rung_matched(db):
    assert search.products(db, "TestPLC 9000 Panel")[0].method == "exact"
    assert search.products(db, "TestPLC 9000")[0].method == "prefix"
    assert search.products(db, "panel 9000")[0].method == "tokens"
    assert search.products(db, "Panel")[0].method == "substring"


def test_a_one_word_query_never_claims_the_token_rung(db):
    """Rung 3 needs two words to mean anything, as match.py's rung 3 does."""
    assert all(hit.method != "tokens" for hit in search.products(db, "TestPLC"))


def test_products_can_be_scoped_to_one_vendor(db):
    assert search.products(db, "Widgetron 500", vendor="Other Industries")
    assert search.products(db, "Widgetron 500", vendor="Testco Electric") == []
    # Unscoped, both vendors who name a Widgetron 500 are listed separately.
    unscoped = [hit for hit in search.products(db, "Widgetron 500")
                if hit.name == "Widgetron 500"]
    assert len(unscoped) == 2


def test_products_abstains_on_a_vendor_that_normalises_to_nothing(db):
    """"GmbH" is a stripped suffix; scoping on "" would answer a different question."""
    assert index.normalize_vendor("GmbH") == ""
    assert search.products(db, "TestPLC", vendor="GmbH") == []


# --- order numbers -----------------------------------------------------------

def test_order_numbers_finds_an_exact_number(db):
    hits = search.order_numbers(db, "TC-9000-A1")
    assert hits[0].method == "exact"
    assert hits[0].order_numbers == ("TC-9000-A1",)
    assert hits[0].name == "TestPLC 9000 (TC-9000-A1)"
    assert hits[0].vendor == "Testco Electric"


def test_order_numbers_finds_a_fragment(db):
    assert search.order_numbers(db, "TC9000")[0].method == "prefix"
    assert search.order_numbers(db, "C9000A1")[0].method == "substring"


def test_order_numbers_normalises_punctuation_and_case(db):
    """Proof that index.normalize_order_number is reused, not reimplemented."""
    spellings = ["tc 9000 a1", "TC-9000-A1", "tc9000a1", "TC.9000.A1"]
    results = [search.order_numbers(db, text) for text in spellings]
    assert all(result == results[0] for result in results)
    assert results[0][0].order_numbers == ("TC-9000-A1",)


def test_order_numbers_counts_advisories_not_entries(db):
    hit = search.order_numbers(db, "TC-9000-A1")[0]
    assert hit.advisories == 2          # two advisories, one product


# --- suggestions -------------------------------------------------------------

def test_suggest_offers_the_closest_vendor(db):
    """"Tesco" is not a substring of "testco", so only edit distance can save it."""
    found = search.suggest(db, vendor="Tesco Electric")
    assert found["vendor_known"] is False
    assert found["vendors"][0].vendor == "Testco Electric"
    assert found["vendors"][0].method == "similar"
    assert found["vendors"][0].similarity >= search.SIMILAR_CUTOFF


def test_suggest_abstains_when_nothing_is_close(db):
    """Nothing is invented to fill the space."""
    found = search.suggest(db, vendor="Zzzqqq")
    assert found["vendors"] == []
    assert "No vendor in the corpus matches" in search.format_suggestions(found)


def test_suggest_does_not_offer_vendors_for_a_known_vendor(db):
    """The name is what failed here, so rival manufacturers answer nothing."""
    found = search.suggest(db, vendor="Testco Electric", product="Nonesuch 1")
    assert found["vendor_known"] is True
    assert found["vendors"] == []
    assert "Closest vendors" not in search.format_suggestions(found)


def test_suggest_scopes_products_to_a_known_vendor(db):
    found = search.suggest(db, vendor="Other Industries", product="Widgetron 999")
    assert [hit.vendor for hit in found["products"]] == ["Other Industries"]


def test_suggest_orders_by_similarity_then_corpus_weight(db):
    """Simens scores higher than Siemens; a bigger corpus footprint outranks it.

    Six hundredths of a difflib ratio is not evidence of anything, so the ratio
    is rounded to a tenth and the advisory count breaks the tie.
    """
    hits = search.suggest(db, vendor="Seimens")["vendors"]
    assert [hit.vendor for hit in hits] == ["Siemens", "Simens"]
    assert hits[0].similarity < hits[1].similarity
    assert hits[0].advisories > hits[1].advisories
    ordering = [(-round(hit.similarity, 1), -hit.advisories) for hit in hits]
    assert ordering == sorted(ordering)


def test_suggest_recovers_a_typo_in_a_multi_word_product_name(db):
    """The word rungs, not edit distance, are what carry product names."""
    found = search.suggest(db, vendor="Siemens", product="SIMATC S7-1500")
    assert found["products"][0].name == "SIMATIC S7-1500"


# --- abstention and limits ---------------------------------------------------

@pytest.mark.parametrize("query", ["-", "%", "_", "__", "", "  "])
def test_a_punctuation_only_query_matches_nothing(db, query):
    """A wildcard reaching a LIKE would widen the search to the whole corpus."""
    assert search.vendors(db, query) == []
    assert search.products(db, query) == []
    assert search.order_numbers(db, query) == []
    found = search.suggest(db, vendor=query, product=query)
    assert found["vendors"] == [] and found["products"] == []


def test_limit_caps_the_results(db):
    assert len(search.vendors(db, "Testco", limit=1)) == 1
    assert len(search.products(db, "TestPLC 9000", limit=1)) == 1
    assert len(search.order_numbers(db, "9000A1", limit=1)) == 1


def test_everything_survives_an_empty_index(empty):
    assert search.vendors(empty, "Siemens") == []
    assert search.products(empty, "S7-1500") == []
    assert search.order_numbers(empty, "6ES7518") == []
    found = search.suggest(empty, vendor="Siemens", product="S7-1500")
    assert found == {"vendor": "Siemens", "product": "S7-1500",
                     "vendor_known": False, "vendors": [], "products": []}
    for text in (search.format_vendors([], "Siemens"),
                 search.format_products([], "S7-1500"),
                 search.format_order_numbers([], "6ES7518"),
                 search.format_suggestions(found)):
        assert "corpus" in text


# --- printable output --------------------------------------------------------

def test_format_vendors_prints_aligned_headings(db):
    hits = search.vendors(db, "Testco")
    lines = search.format_vendors(hits, "Testco").splitlines()
    heading = lines[2]
    for column in ("VENDOR", "PRODUCTS", "ADVISORIES", "MATCHED BY"):
        assert column in heading
    # Each count sits inside the span of its own heading, which is what makes
    # the table readable when the vendor names are of wildly different lengths.
    for hit, line in zip(hits, lines[3:]):
        for column, value in (("PRODUCTS", hit.products),
                              ("ADVISORIES", hit.advisories)):
            start = heading.index(column)
            assert line[start:start + len(column)].strip() == f"{value:,}"


def test_format_products_shows_the_order_number_and_the_method(db):
    text = search.format_products(
        search.products(db, "TestPLC 9000 (TC-9000-A1)"), "TestPLC 9000")
    assert "Testco Electric" in text
    assert "9000-A1 +1" in text          # the first number, and how many more
    assert "exact" in text


def test_format_order_numbers_names_the_product_it_found(db):
    text = search.format_order_numbers(search.order_numbers(db, "TC9000"), "TC9000")
    assert "TC-9000-A1" in text
    assert "TestPLC 9000 (TC-9000-A1)" in text


def test_format_suggestions_says_when_nothing_was_asked(db):
    assert search.format_suggestions(search.suggest(db)) == \
        "Nothing to suggest: no vendor or product was given."


def test_advisory_count_is_singular_for_one(db):
    text = search.format_products(search.products(db, "Gateway 10"), "Gateway 10")
    assert "1 advisory" in text
    assert "1 advisories" not in text


def test_formatted_output_stays_within_eighty_columns(db):
    """Long names must be clipped, not allowed to wreck the alignment."""
    long_hits = [search.Hit("substring", vendor="ABB, Phoenix Contact, Schneider "
                            "Electric, Siemens, and WAGO",
                            name="SIPLUS S7-1500 CPU 1518-4 PN/DP MFP RAIL "
                                 "(6AG1518-4AX00-4AC0) and related families",
                            order_numbers=("6AG15184AX004AC0", "6AG15184AX004AC1"),
                            advisories=16, products=11, similarity=0.86)]
    texts = [search.format_vendors(long_hits, "abb"),
             search.format_products(long_hits, "siplus"),
             search.format_order_numbers(long_hits, "6AG1518"),
             search.format_vendors(search.vendors(db, "Testco"), "Testco"),
             search.format_suggestions(search.suggest(db, vendor="Seimens",
                                                      product="SIMATC S7-1500"))]
    for text in texts:
        for line in text.splitlines():
            assert len(line) <= 78, line


def test_a_clipped_name_is_visibly_clipped(db):
    """A truncated name read as a whole one would be a wrong answer."""
    hit = search.Hit("exact", vendor="V" * 40, name="N" * 80)
    assert "..." in search.format_products([hit], "n")
