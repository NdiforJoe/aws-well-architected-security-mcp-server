from src.mappings import map_to_nist_soc2


def test_map_to_nist_soc2_known_finding():
    findings = [
        {"id": "IAM-ROOT-MFA", "severity": "Critical", "description": "Root MFA missing"}
    ]

    mapped = map_to_nist_soc2(findings)

    assert mapped[0]["nist_csf"] == "PR.AC-01"
    assert mapped[0]["nist_function"] == "Protect"
    assert mapped[0]["soc2"] == "CC6.1"


def test_map_to_nist_soc2_unknown_finding():
    findings = [
        {"id": "UNKNOWN", "severity": "Medium"}
    ]

    mapped = map_to_nist_soc2(findings)

    assert mapped[0]["nist_csf"] == "Unknown"
    assert mapped[0]["soc2"] == "Unknown"