"""Gateway monitoring utilities."""

import threading
import time
from typing import Optional

from utils.network_utils import resolve_mac


class GatewayMonitor:
    """Tracks default gateway MAC changes over time."""

    def __init__(self, gateway_ip: str, poll_interval: int = 5):
        self.gateway_ip = gateway_ip
        self.poll_interval = poll_interval
        self.original_mac: Optional[str] = None
        self.current_mac: Optional[str] = None
        self.gateway_changed = 0
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def initialize(self) -> None:
        """Capture initial gateway MAC address at startup."""
        mac = resolve_mac(self.gateway_ip)
        if mac is None:
            raise RuntimeError(f"Could not resolve gateway MAC for {self.gateway_ip}")
        self.original_mac = mac
        self.current_mac = mac

    def start(self) -> threading.Thread:
        """Start gateway monitor thread."""
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """Signal monitor thread to stop."""
        self._stop_event.set()

    def status(self) -> tuple[int, Optional[str], Optional[str]]:
        """Return gateway change flag and MAC state."""
        with self._lock:
            return self.gateway_changed, self.original_mac, self.current_mac

    def _run(self) -> None:
        while not self._stop_event.is_set():
            latest_mac = resolve_mac(self.gateway_ip)
            if latest_mac:
                with self._lock:
                    self.current_mac = latest_mac
                    if self.original_mac and latest_mac.lower() != self.original_mac.lower():
                        self.gateway_changed = 1
            time.sleep(self.poll_interval)
