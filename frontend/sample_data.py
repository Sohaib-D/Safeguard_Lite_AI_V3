from __future__ import annotations

import random
from typing import Any, TypedDict

SYSTEM_RANDOM = random.SystemRandom()

# These are the EXACT raw input columns the model bundle's preprocessor expects.
# Numeric: f0..f9  |  Categorical: service
NUMERIC_FEATURES = ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9"]
CATEGORICAL_FEATURE = "service"


class AttackProfile(TypedDict):
    ranges: dict[str, tuple[float, float]]
    services: list[str]


ATTACK_PROFILES: dict[str, AttackProfile] = {
    "Normal": {
        "ranges": {
            "f0": (0.0, 0.4), "f1": (0.0, 0.5), "f2": (0.0, 0.4), "f3": (0.0, 0.5),
            "f4": (0.0, 0.6), "f5": (0.0, 0.5), "f6": (0.0, 0.6), "f7": (0.0, 0.5),
            "f8": (0.0, 0.4), "f9": (0.0, 0.5),
        },
        "services": ["http", "dns"],
    },
    "DDoS": {
        "ranges": {
            "f0": (0.7, 1.6), "f1": (0.8, 1.8), "f2": (0.4, 1.4), "f3": (0.7, 1.9),
            "f4": (0.4, 1.6), "f5": (0.6, 1.7), "f6": (0.8, 2.0), "f7": (0.5, 1.7),
            "f8": (0.5, 1.6), "f9": (0.8, 1.9),
        },
        "services": ["http", "dns", "ssh"],
    },
    "PortScan": {
        "ranges": {
            "f0": (-0.4, 0.9), "f1": (0.6, 1.6), "f2": (0.7, 1.7), "f3": (0.3, 1.3),
            "f4": (0.1, 1.2), "f5": (0.2, 1.4), "f6": (0.1, 1.5), "f7": (0.8, 1.8),
            "f8": (0.6, 1.7), "f9": (0.2, 1.4),
        },
        "services": ["dns", "ssh"],
    },
    "BruteForce": {
        "ranges": {
            "f0": (0.2, 1.1), "f1": (-0.2, 0.9), "f2": (0.5, 1.3), "f3": (0.7, 1.6),
            "f4": (0.8, 1.8), "f5": (0.5, 1.4), "f6": (0.4, 1.4), "f7": (0.1, 1.0),
            "f8": (0.6, 1.5), "f9": (0.7, 1.8),
        },
        "services": ["ssh", "http"],
    },
}


def build_live_record(schema: dict[str, Any] = None, attack_label: str = "Normal") -> dict[str, Any]:
    """Generate one record shaped to what the ML model bundle expects.
    
    Produces keys: f0..f9 (numeric) + service (categorical).
    The schema parameter is kept for backward compatibility but is no longer required.
    """
    profile = ATTACK_PROFILES.get(attack_label, ATTACK_PROFILES["Normal"])

    record: dict[str, Any] = {}
    for col in NUMERIC_FEATURES:
        low, high = profile["ranges"].get(col, (0.0, 1.0))
        record[col] = round(SYSTEM_RANDOM.uniform(low, high), 4)
    record[CATEGORICAL_FEATURE] = SYSTEM_RANDOM.choice(profile["services"])
    return record


def generate_live_records(
    schema: dict[str, Any] = None, attack_label: str = "Normal", count: int = 1
) -> list[dict[str, Any]]:
    return [build_live_record(schema=schema, attack_label=attack_label) for _ in range(count)]
