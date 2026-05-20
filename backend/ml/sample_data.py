"""
Sample data generators for each attack profile.

Each profile produces statistically distinct feature vectors matching
the patterns the model was trained on:

  Schema: f0..f9 (10 numeric) + service (categorical: dns/http/ssh)
  Classes: BruteForce, DDoS, Normal, PortScan

Per-class means from training data (already standardised):
  BruteForce:  f0≈1.0   f1≈1.0   f2≈-1.0  f3≈-1.0  f4≈-0.1  f5≈0.8   f6≈1.2   f7≈-0.5  f8≈0.0   f9≈0.9
  DDoS:        f0≈-0.9  f1≈1.2   f2≈-2.9  f3≈1.1   f4≈-0.1  f5≈-0.9  f6≈-1.0  f7≈-1.2  f8≈0.0   f9≈-0.7
  Normal:      f0≈1.1   f1≈-1.0  f2≈-1.1  f3≈0.8   f4≈0.1   f5≈1.0   f6≈0.9   f7≈-1.0  f8≈0.05  f9≈1.1
  PortScan:    f0≈0.9   f1≈-1.0  f2≈1.6   f3≈-1.0  f4≈0.06  f5≈0.9   f6≈1.0   f7≈-1.1  f8≈-0.2  f9≈-1.0
"""

from __future__ import annotations

import random
from typing import Any, Dict, List


# ── Feature columns (must match model's preprocessor) ────────────────────────
NUMERIC_FEATURES = [f"f{i}" for i in range(10)]  # f0..f9
CATEGORICAL_FEATURE = "service"
CATEGORICAL_VALUES = ["dns", "http", "ssh"]


def _rand(lo: float, hi: float) -> float:
    """Uniform random in [lo, hi] rounded to 4 decimals."""
    return round(random.uniform(lo, hi), 4)


# ── Per-profile generators ───────────────────────────────────────────────────
# Value ranges are mean ± ~1 std from the training data.

def _normal_profile() -> Dict[str, Any]:
    """Normal traffic: f0≈+1.1, f1≈-1, f2≈-1.1, f3≈+0.8, f5≈+1, f6≈+0.9, f9≈+1.1"""
    return {
        "f0": _rand(0.4, 1.8),     # high positive
        "f1": _rand(-1.8, -0.3),   # negative
        "f2": _rand(-1.8, -0.4),   # negative
        "f3": _rand(0.1, 1.5),     # positive
        "f4": _rand(-0.8, 1.0),    # near zero
        "f5": _rand(0.3, 1.7),     # high positive
        "f6": _rand(0.2, 1.6),     # positive
        "f7": _rand(-1.7, -0.3),   # negative
        "f8": _rand(-0.6, 0.7),    # near zero
        "f9": _rand(0.4, 1.8),     # high positive
        CATEGORICAL_FEATURE: random.choice(["ssh", "ssh", "http", "dns"]),  # biased ssh
    }


def _ddos_profile() -> Dict[str, Any]:
    """DDoS: f0≈-0.9, f1≈+1.2, f2≈-2.9, f3≈+1.1, f5≈-0.9, f6≈-1, f7≈-1.2, f9≈-0.7"""
    return {
        "f0": _rand(-1.6, -0.2),   # negative (distinctive)
        "f1": _rand(0.4, 2.0),     # high positive
        "f2": _rand(-3.5, -2.0),   # very negative (key discriminator)
        "f3": _rand(0.3, 1.8),     # positive
        "f4": _rand(-1.0, 0.8),    # near zero
        "f5": _rand(-1.6, -0.2),   # negative
        "f6": _rand(-1.7, -0.3),   # negative
        "f7": _rand(-1.9, -0.5),   # negative
        "f8": _rand(-0.6, 0.7),    # near zero
        "f9": _rand(-1.4, 0.0),    # negative
        CATEGORICAL_FEATURE: random.choice(["dns", "dns", "http", "ssh"]),  # biased dns
    }


def _bruteforce_profile() -> Dict[str, Any]:
    """BruteForce: f0≈+1, f1≈+1, f2≈-1, f3≈-1, f6≈+1.2, f9≈+0.9"""
    return {
        "f0": _rand(0.3, 1.7),     # positive
        "f1": _rand(0.2, 1.7),     # positive (unlike Normal/PortScan)
        "f2": _rand(-1.7, -0.3),   # negative
        "f3": _rand(-1.7, -0.3),   # negative (unlike Normal)
        "f4": _rand(-1.0, 0.7),    # near zero
        "f5": _rand(0.1, 1.4),     # positive
        "f6": _rand(0.5, 1.9),     # high positive (key discriminator)
        "f7": _rand(-1.2, 0.3),    # slightly negative
        "f8": _rand(-0.7, 0.6),    # near zero
        "f9": _rand(0.2, 1.6),     # positive
        CATEGORICAL_FEATURE: random.choice(["dns", "http", "ssh"]),  # balanced
    }


def _portscan_profile() -> Dict[str, Any]:
    """PortScan: f0≈+0.9, f1≈-1, f2≈+1.6, f3≈-1, f9≈-1 (f2 high is key!)"""
    return {
        "f0": _rand(0.2, 1.6),     # positive
        "f1": _rand(-1.7, -0.3),   # negative
        "f2": _rand(0.9, 2.3),     # HIGH positive (key discriminator)
        "f3": _rand(-1.7, -0.3),   # negative
        "f4": _rand(-0.7, 0.8),    # near zero
        "f5": _rand(0.2, 1.6),     # positive
        "f6": _rand(0.3, 1.7),     # positive
        "f7": _rand(-1.8, -0.4),   # negative
        "f8": _rand(-0.9, 0.4),    # slightly negative
        "f9": _rand(-1.7, -0.3),   # negative (key discriminator)
        CATEGORICAL_FEATURE: random.choice(["http", "http", "dns", "ssh"]),  # biased http
    }


# ── Profile registry ─────────────────────────────────────────────────────────

_PROFILE_GENERATORS = {
    "Normal": _normal_profile,
    "Normal Traffic": _normal_profile,
    "DDoS": _ddos_profile,
    "DoS / DDoS": _ddos_profile,
    "BruteForce": _bruteforce_profile,
    "Brute Force": _bruteforce_profile,
    "PortScan": _portscan_profile,
    "Port Scan": _portscan_profile,
}


def generate_features(profile: str = "Normal") -> Dict[str, Any]:
    """Generate a single feature vector for the given attack profile.

    Args:
        profile: One of "Normal", "DDoS", "BruteForce", "PortScan"
                 (or their display aliases like "DoS / DDoS").

    Returns:
        Dict matching the model's raw input schema (f0..f9 + service).
    """
    generator = _PROFILE_GENERATORS.get(profile, _normal_profile)
    return generator()


def generate_batch(profile: str = "Normal", count: int = 10) -> List[Dict[str, Any]]:
    """Generate multiple feature vectors for the given profile."""
    return [generate_features(profile) for _ in range(count)]


# All known profile names (canonical names matching label_classes)
PROFILE_NAMES: List[str] = ["Normal", "DDoS", "BruteForce", "PortScan"]

# Display-friendly aliases (for UI dropdowns)
PROFILE_DISPLAY_NAMES: List[str] = [
    "Normal Traffic", "DoS / DDoS", "Brute Force", "Port Scan",
]
