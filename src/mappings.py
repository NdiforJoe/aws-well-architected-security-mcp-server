def map_to_nist_soc2(findings: list[dict]) -> list[dict]:
    """Map findings to NIST CSF 2.0 and SOC 2 TSC."""
    nist_soc_map = {
        "IAM-ROOT-MFA": {
            "nist_csf": "PR.AC-01",
            "nist_function": "Protect",
            "soc2": "CC6.1",
            "description": "Identity & Access Control"
        },
        # Add more as we expand checks
    }

    for finding in findings:
        key = finding.get("id")
        if key in nist_soc_map:
            finding.update(nist_soc_map[key])
        else:
            finding["nist_csf"] = "Unknown"
            finding["soc2"] = "Unknown"

    return findings