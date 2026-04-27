"""ARP anomaly detector."""

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Set

from colorama import Fore, Style
from scapy.all import ARP, sniff

from detector.risk_engine import RiskEngine


class ArpDetector:
    """Detects ARP spoofing and suspicious ARP behavior."""

    def __init__(self, logger, gateway_monitor, time_window_seconds: int = 30):
        self.logger = logger
        self.gateway_monitor = gateway_monitor
        self.time_window_seconds = time_window_seconds

        self.ip_to_mac: Dict[str, str] = {}
        self.ip_conflicts: Dict[str, Set[str]] = defaultdict(set)
        self.suspicious_events: Deque[float] = deque()
        self.recent_reasons: Deque[str] = deque(maxlen=10)

        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start packet sniffing loop."""
        sniff(
            filter="arp",
            store=False,
            prn=self._process_packet,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def stop(self) -> None:
        """Stop packet processing."""
        self._stop_event.set()

    def run_simulation(self, interval_seconds: int = 2) -> None:
        """Generate fake anomalies for demo/testing without live sniffing."""
        print("Simulation mode enabled: generating demo anomaly events...\n")

        scenarios = [
            {
                "attack_type": "ARP Spoofing",
                "ip": "192.168.1.20",
                "mac": "aa:bb:cc:11:22:33",
                "reason": "IP 192.168.1.20 changed MAC from 10:10:10:10:10:10 to aa:bb:cc:11:22:33.",
                "gateway_changed": 0,
                "duplicate_conflicts": 1,
                "frequency": 1,
                "event_type": "IP-MAC Conflict",
            },
            {
                "attack_type": "ARP Spoofing",
                "ip": "192.168.1.33",
                "mac": "de:ad:be:ef:00:01",
                "reason": "Multiple conflicting ARP replies observed for IP 192.168.1.33.",
                "gateway_changed": 0,
                "duplicate_conflicts": 2,
                "frequency": 2,
                "event_type": "Suspicious ARP Burst",
            },
            {
                "attack_type": "Gateway Attack",
                "ip": "192.168.1.1",
                "mac": "66:66:66:66:66:66",
                "reason": "Gateway MAC changed from 44:44:44:44:44:44 to 66:66:66:66:66:66. This may indicate MITM activity.",
                "gateway_changed": 1,
                "duplicate_conflicts": 2,
                "frequency": 3,
                "event_type": "Gateway MAC Change",
            },
        ]

        for item in scenarios:
            if self._stop_event.is_set():
                break

            risk = RiskEngine.calculate(
                item["gateway_changed"],
                item["duplicate_conflicts"],
                item["frequency"],
            )
            self._emit_alert(
                attack_type=item["attack_type"],
                ip=item["ip"],
                mac=item["mac"],
                score=risk.score,
                level=risk.level,
                reason=item["reason"],
            )
            self.logger.warning(
                "event_type=%s risk_score=%s risk_level=%s details=%s ip=%s mac=%s",
                item["event_type"],
                risk.score,
                risk.level,
                item["reason"],
                item["ip"],
                item["mac"],
            )
            time.sleep(interval_seconds)

    def _process_packet(self, packet) -> None:
        if not packet.haslayer(ARP):
            return

        arp_layer = packet[ARP]
        ip = arp_layer.psrc
        mac = arp_layer.hwsrc

        if not ip or not mac:
            return

        now = time.time()
        event_type = "ARP Observation"
        reason = ""
        attack_type = "ARP Spoofing"
        duplicate_conflicts = 0

        with self._lock:
            self._prune_old_events(now)

            known_mac = self.ip_to_mac.get(ip)
            if known_mac is None:
                self.ip_to_mac[ip] = mac
            elif known_mac.lower() != mac.lower():
                self.ip_conflicts[ip].update({known_mac.lower(), mac.lower()})
                self.ip_to_mac[ip] = mac
                self.suspicious_events.append(now)
                reason = f"IP {ip} changed MAC from {known_mac} to {mac}."
                self.recent_reasons.append(reason)
                event_type = "IP-MAC Conflict"

            duplicate_conflicts = self._count_duplicate_conflicts()
            frequency = len(self.suspicious_events)

        gateway_changed, gateway_original, gateway_current = self.gateway_monitor.status()
        risk = RiskEngine.calculate(gateway_changed, duplicate_conflicts, frequency)

        if gateway_changed == 1:
            attack_type = "Gateway Attack"
            reason = (
                f"Gateway MAC changed from {gateway_original} to {gateway_current}. "
                "This may indicate MITM activity."
            )
            event_type = "Gateway MAC Change"
        elif reason:
            attack_type = "ARP Spoofing"
        else:
            # Keep logs cleaner by only alerting on suspicious states.
            return

        self._emit_alert(
            attack_type=attack_type,
            ip=ip,
            mac=mac,
            score=risk.score,
            level=risk.level,
            reason=reason,
        )

        self.logger.warning(
            "event_type=%s risk_score=%s risk_level=%s details=%s ip=%s mac=%s",
            event_type,
            risk.score,
            risk.level,
            reason,
            ip,
            mac,
        )

    def _count_duplicate_conflicts(self) -> int:
        """Count how many IPs currently have >1 observed MAC."""
        count = 0
        for _ip, macs in self.ip_conflicts.items():
            if len(macs) > 1:
                count += 1
        return count

    def _prune_old_events(self, now: float) -> None:
        """Keep only events in rolling time window."""
        while self.suspicious_events and (now - self.suspicious_events[0]) > self.time_window_seconds:
            self.suspicious_events.popleft()

    @staticmethod
    def _level_color(level: str) -> str:
        if level == "LOW":
            return Fore.GREEN
        if level == "MEDIUM":
            return Fore.YELLOW
        return Fore.RED

    def _emit_alert(
        self,
        attack_type: str,
        ip: str,
        mac: str,
        score: int,
        level: str,
        reason: str,
    ) -> None:
        color = self._level_color(level)
        print(
            f"{color}[ALERT] Attack Type: {attack_type} | IP: {ip} | MAC: {mac} | "
            f"Risk Score: {score} | Risk Level: {level}{Style.RESET_ALL}"
        )
        print(f"{color}Reason: {reason}{Style.RESET_ALL}")
        print(
            f"{color}⚠️ Warning: Your network may be compromised. Consider disconnecting.{Style.RESET_ALL}"
        )
        if level == "HIGH":
            print(f"{color}Recommendation: Disconnect from this Wi-Fi and reconnect on a trusted network.{Style.RESET_ALL}")
