

def test_shipped_fixes_filed_as_mitigations_are_recognised_broadly():
    """CISA and vendors file real patches under 'mitigation' across many
    phrasings, not just Moxa's. The reader must catch the shipped-fix language
    while refusing promises and non-fixes -- the Moxa bug was one of thousands."""
    from retrust import csaf
    shipped = [
        "Siemens has released a new version. Update to V2.0 or later.",
        "Schneider Electric released firmware v1.5.1.0",
        "Update to the latest version.",
        "Upgrade to one of the corrected versions.",
        "Download the new firmware from the vendor portal.",
        "This issue is fixed in version 3.4.",
        "A patch is available.",
        "Install firmware patch. Patches may be requested from Customer Service.",
    ]
    not_shipped = [
        "There is no fixed version available yet.",
        "A patch will be released in a future update.",
        "This component cannot be patched; restrict network access.",
        "Restrict network access and monitor for anomalies.",
        "Affected in version 2.0 and earlier.",
        "This product is end-of-life and no longer supported.",
    ]
    assert all(csaf._names_a_shipped_fix(t) for t in shipped)
    assert not any(csaf._names_a_shipped_fix(t) for t in not_shipped)
