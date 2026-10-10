"""
@ai-role Statistical Entropy & Obfuscation Anomaly Scorer for Blue Team EDR/SIEM
@ai-flow Byte Analysis -> Shannon Entropy -> Character Frequency Density -> Threat Rating
@ai-boundary Pure static analysis (Zero execution)
@ai-invariant Deterministic floating point scoring for SOC triage
"""

from __future__ import annotations
import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class AnomalyScoreResult:
    shannon_entropy: float
    caret_density: float
    delimiter_density: float
    var_expansion_density: float
    composite_threat_score: float
    threat_level: str
    triggered_anomalies: List[str]


def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return round(-sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values()), 4)


def analyze_script_telemetry(raw_bytes: bytes) -> AnomalyScoreResult:
    text = raw_bytes.decode("utf-8", errors="replace")
    total_len = max(len(text), 1)

    entropy = calculate_shannon_entropy(raw_bytes)
    caret_count = text.count("^")
    var_count = text.count("%") + text.count("!")
    delimiter_count = text.count(",") + text.count(";") + text.count("=")

    caret_density = round(caret_count / total_len, 4)
    var_density = round(var_count / total_len, 4)
    delimiter_density = round(delimiter_count / total_len, 4)

    anomalies: List[str] = []
    score = 0.0

    # 1. Entropy score (Natural batch is usually between 4.0 and 4.8; obfuscated > 5.1)
    if entropy > 5.3:
        score += 35.0
        anomalies.append(f"High Shannon Entropy: {entropy} (> 5.3)")
    elif entropy > 5.0:
        score += 20.0
        anomalies.append(f"Elevated Shannon Entropy: {entropy} (> 5.0)")

    # 2. Caret density
    if caret_density > 0.04:
        score += 35.0
        anomalies.append(f"Severe Caret Density: {caret_density * 100:.1f}% of total chars")
    elif caret_density > 0.015:
        score += 20.0
        anomalies.append(f"Elevated Caret Density: {caret_density * 100:.1f}%")

    # 3. Variable expansion density
    if var_density > 0.08:
        score += 25.0
        anomalies.append(f"Heavy Variable Expansion Density: {var_density * 100:.1f}%")
    elif var_density > 0.04:
        score += 15.0
        anomalies.append(f"Moderate Variable Expansion: {var_density * 100:.1f}%")

    # 4. Delimiter collapsing
    if delimiter_density > 0.06:
        score += 15.0
        anomalies.append(f"Anomalous Delimiter Density: {delimiter_density * 100:.1f}%")

    # 5. Polyglot BOM check
    if raw_bytes.startswith(b"\xff\xfe") and raw_bytes[2:10].count(0) < 2:
        score += 40.0
        anomalies.append("BatCloak UTF-16LE Polyglot Disguise Detected (0xFF 0xFE)")

    composite = min(round(score, 1), 100.0)

    if composite >= 75.0:
        level = "CRITICAL_OBFUSCATION"
    elif composite >= 50.0:
        level = "HIGH_ANOMALY"
    elif composite >= 25.0:
        level = "SUSPICIOUS"
    else:
        level = "BENIGN"

    return AnomalyScoreResult(
        shannon_entropy=entropy,
        caret_density=caret_density,
        delimiter_density=delimiter_density,
        var_expansion_density=var_density,
        composite_threat_score=composite,
        threat_level=level,
        triggered_anomalies=anomalies,
    )
