"""GRC layer: maps finding categories and the CI gate itself to security controls.

IMPORTANT: this provides *evidence supporting* controls. SecureFlow never states that an
organisation is "compliant" or "certified" - that is an assessor's judgement, not a tool's.
Mapping is static, documented and deliberately small (two frameworks, tags only).
"""

CONTROLS: dict[str, dict] = {
    # ISO/IEC 27001:2022 Annex A
    "A.5.17": {"framework": "ISO 27001:2022", "title": "Authentication information"},
    "A.5.21": {"framework": "ISO 27001:2022", "title": "Managing information security in the ICT supply chain"},
    "A.8.8": {"framework": "ISO 27001:2022", "title": "Management of technical vulnerabilities"},
    "A.8.9": {"framework": "ISO 27001:2022", "title": "Configuration management"},
    "A.8.25": {"framework": "ISO 27001:2022", "title": "Secure development life cycle"},
    "A.8.28": {"framework": "ISO 27001:2022", "title": "Secure coding"},
    "A.8.29": {"framework": "ISO 27001:2022", "title": "Security testing in development and acceptance"},
    "A.8.32": {"framework": "ISO 27001:2022", "title": "Change management"},
    # NIST Cybersecurity Framework 2.0
    "ID.RA-01": {"framework": "NIST CSF 2.0", "title": "Vulnerabilities in assets are identified, validated, and recorded"},
    "ID.RA-06": {"framework": "NIST CSF 2.0", "title": "Risk responses are chosen, prioritized, planned, tracked, and communicated"},
    "PR.AA-01": {"framework": "NIST CSF 2.0", "title": "Identities and credentials are managed"},
    "PR.PS-06": {"framework": "NIST CSF 2.0", "title": "Secure software development practices are integrated and monitored"},
}

CATEGORY_CONTROLS: dict[str, list[str]] = {
    "code": ["A.8.28", "A.8.29", "ID.RA-01", "PR.PS-06"],
    "dependency": ["A.8.8", "A.5.21", "ID.RA-01"],
    "secret": ["A.5.17", "PR.AA-01"],
    "container": ["A.8.8", "A.8.9", "ID.RA-01"],
}

# Controls evidenced by the existence of the automated gate itself (every evaluated run).
GATE_CONTROLS: list[str] = ["A.8.25", "A.8.32", "A.8.29", "PR.PS-06", "ID.RA-06"]

DISCLAIMER = (
    "These mappings show where SecureFlow produces evidence relevant to a control. "
    "They do not establish compliance with, or certification against, any standard."
)


def controls_for_category(category: str) -> list[dict]:
    return [{"id": cid, **CONTROLS[cid]} for cid in CATEGORY_CONTROLS.get(category, [])]
