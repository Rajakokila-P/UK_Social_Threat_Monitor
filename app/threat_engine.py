import re

from langdetect import detect


def _term_present(term: str, text_lower: str) -> bool:
    return re.search(r"\b" + re.escape(term) + r"\b", text_lower) is not None


THREAT_TERMS = {
    "critical": [
        "bomb",
        "explosive",
        "mass attack",
        "shoot everyone",
        "terror attack",
    ],
    "high": [
        "attack",
        "kill",
        "shoot",
        "destroy",
        "stab",
    ],
    "medium": [
        "hack",
        "ransomware",
        "phishing",
        "breach",
        "weapon",
    ],
}


UK_TERMS = [
    "uk",
    "united kingdom",
    "britain",
    "british",
    "england",
    "scotland",
    "wales",
    "northern ireland",
    "london",
    "manchester",
    "birmingham",
    "liverpool",
]


def detect_language(text: str) -> str:
    try:
        return detect(text)
    except Exception:
        return "unknown"


def check_uk_relevance(text: str) -> bool:
    text_lower = text.lower()

    return any(
        _term_present(term, text_lower)
        for term in UK_TERMS
    )


def analyse_threat(text: str):
    text_lower = text.lower()

    detected_terms = []
    severity = "low"

    for term in THREAT_TERMS["critical"]:
        if _term_present(term, text_lower):
            detected_terms.append(term)
            severity = "critical"

    if severity != "critical":
        for term in THREAT_TERMS["high"]:
            if _term_present(term, text_lower):
                detected_terms.append(term)
                severity = "high"

    if severity not in ["critical", "high"]:
        for term in THREAT_TERMS["medium"]:
            if _term_present(term, text_lower):
                detected_terms.append(term)
                severity = "medium"

    uk_relevant = check_uk_relevance(text)

    return {
        "language": detect_language(text),
        "uk_relevant": uk_relevant,
        "severity": severity,
        "detected_terms": detected_terms,
        "human_review_required": severity in [
            "medium",
            "high",
            "critical",
        ],
    }


def calculate_risk_score(text: str, uk_relevant: bool):
    text_lower = text.lower()

    score = 0
    indicators = []

    violent_terms = [
        "attack",
        "kill",
        "shoot",
        "stab",
        "bomb",
        "destroy",
    ]

    for term in violent_terms:
        if _term_present(term, text_lower):
            score += 25
            indicators.append(f"violent_term:{term}")
            break

    weapon_terms = [
        "gun",
        "rifle",
        "knife",
        "weapon",
        "explosive",
        "bomb",
    ]

    for term in weapon_terms:
        if _term_present(term, text_lower):
            score += 20
            indicators.append(f"weapon_reference:{term}")
            break

    time_terms = [
        "today",
        "tonight",
        "tomorrow",
        "this evening",
        "this morning",
        "now",
    ]

    for term in time_terms:
        if _term_present(term, text_lower):
            score += 15
            indicators.append(f"time_reference:{term}")
            break

    if uk_relevant:
        score += 15
        indicators.append("uk_relevant")

    cyber_terms = [
        "ransomware",
        "ddos",
        "malware",
        "hack",
        "phishing",
    ]

    for term in cyber_terms:
        if _term_present(term, text_lower):
            score += 15
            indicators.append(f"cyber_indicator:{term}")
            break

    score = min(score, 100)

    if score >= 75:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risk_indicators": indicators,
    }