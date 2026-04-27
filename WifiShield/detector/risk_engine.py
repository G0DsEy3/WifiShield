"""Risk scoring engine for Wifishield."""

from dataclasses import dataclass


@dataclass
class RiskResult:
    """Container for risk score output."""

    score: int
    level: str


class RiskEngine:
    """Computes risk score using weighted indicators."""

    W1 = 5  # Gateway change
    W2 = 3  # Duplicate IP-MAC conflicts
    W3 = 2  # Suspicious packet frequency

    @classmethod
    def calculate(cls, gateway_changed: int, duplicate_conflicts: int, frequency: int) -> RiskResult:
        """
        Calculate risk score:
        R = (W1 * G) + (W2 * D) + (W3 * F)
        """
        score = (cls.W1 * gateway_changed) + (cls.W2 * duplicate_conflicts) + (cls.W3 * frequency)

        # Override rule: any gateway MAC change is always HIGH risk.
        if gateway_changed == 1:
            return RiskResult(score=score, level="HIGH")

        if score < 5:
            level = "LOW"
        elif score < 10:
            level = "MEDIUM"
        else:
            level = "HIGH"

        return RiskResult(score=score, level=level)
