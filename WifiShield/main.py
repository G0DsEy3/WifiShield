"""Wifishield entry point."""

import argparse
import os
import platform
import sys

from colorama import Fore, Style, init

from detector.arp_detector import ArpDetector
from detector.gateway_monitor import GatewayMonitor
from utils.logger import setup_logger
from utils.network_utils import get_default_gateway_ip, local_ip


def print_banner() -> None:
    print("=" * 55)
    print("Wifishield - Public WiFi Protection Tool")
    print("=" * 55)


def check_privileges() -> None:
    """
    Packet sniffing requires elevated privileges.
    Linux/macOS: root is required.
    """
    if os.name != "nt":
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print(f"{Fore.RED}Run this tool with sudo/root privileges.{Style.RESET_ALL}")
            print("Example: sudo python main.py")
            sys.exit(1)


class SimulationGatewayMonitor:
    """Simple gateway monitor replacement used in --simulate mode."""

    def status(self):
        return 0, "44:44:44:44:44:44", "44:44:44:44:44:44"

    def start(self):
        return None

    def stop(self):
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wifishield - Public WiFi Protection Tool")
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Run demo mode with generated anomaly alerts (no live packet sniffing).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    init(autoreset=True)
    print_banner()
    if not args.simulate:
        check_privileges()

    logger = setup_logger("logs.txt")
    logger.info("Wifishield started on %s", platform.platform())

    if args.simulate:
        print(f"{Fore.CYAN}Starting simulation mode (no live sniffing)...{Style.RESET_ALL}")
        detector = ArpDetector(
            logger=logger,
            gateway_monitor=SimulationGatewayMonitor(),
            time_window_seconds=30,
        )
        print(f"{Fore.GREEN}Monitoring network for threats...{Style.RESET_ALL}")
        print("Press Ctrl+C to stop.\n")
        try:
            detector.run_simulation(interval_seconds=2)
            print(f"\n{Fore.GREEN}Simulation complete.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print("\nStopping Wifishield simulation...")
            detector.stop()
            logger.info("Wifishield simulation stopped by user.")
        return

    print(f"{Fore.CYAN}Detecting network gateway...{Style.RESET_ALL}")
    gateway_ip = get_default_gateway_ip()
    my_ip = local_ip()
    print(f"Local IP: {my_ip}")
    print(f"Gateway IP: {gateway_ip}")

    gateway_monitor = GatewayMonitor(gateway_ip=gateway_ip, poll_interval=5)
    gateway_monitor.initialize()
    _, original_gateway_mac, _ = gateway_monitor.status()
    print(f"Gateway MAC (baseline): {original_gateway_mac}")

    logger.info("Gateway detected: ip=%s mac=%s", gateway_ip, original_gateway_mac)

    gateway_monitor.start()

    detector = ArpDetector(
        logger=logger,
        gateway_monitor=gateway_monitor,
        time_window_seconds=30,
    )

    print(f"{Fore.GREEN}Monitoring network for threats...{Style.RESET_ALL}")
    print("Press Ctrl+C to stop.\n")

    try:
        detector.start()
    except KeyboardInterrupt:
        print("\nStopping Wifishield...")
        detector.stop()
        gateway_monitor.stop()
        logger.info("Wifishield stopped by user.")
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        print(f"{Fore.RED}Fatal error: {exc}{Style.RESET_ALL}")
        detector.stop()
        gateway_monitor.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
