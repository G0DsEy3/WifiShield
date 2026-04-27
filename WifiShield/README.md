# Wifishield

`Wifishield` is a lightweight, real-time network anomaly detection tool for public Wi-Fi safety.  
It focuses on detecting ARP spoofing and potential Man-in-the-Middle (MITM) behavior by monitoring ARP traffic and gateway integrity.

## Features

- Real-time ARP packet sniffing using Scapy
- IP -> MAC mapping and anomaly detection
- Default gateway MAC baseline + continuous verification
- Rolling suspicious event frequency tracking (30-second window)
- Risk score engine with LOW / MEDIUM / HIGH levels
- Color-coded terminal alerts
- File-based event logging (`logs.txt`)

## Risk Scoring Formula

Wifishield computes risk using:

`R = (W1 * G) + (W2 * D) + (W3 * F)`

Where:

- `G`: Gateway change indicator (`0` or `1`)
- `D`: Duplicate IP-MAC conflicts count
- `F`: Suspicious packet frequency in rolling time window

Weights:

- `W1 = 5`
- `W2 = 3`
- `W3 = 2`

Risk levels:

- `LOW`: `R < 5`
- `MEDIUM`: `5 <= R < 10`
- `HIGH`: `R >= 10`

Override rule:

- If `G = 1`, risk is always `HIGH`.

Example:

- If `G=1`, `D=2`, `F=3`
- `R = (5*1) + (3*2) + (2*3) = 17` -> `HIGH`

## Project Structure

```text
wifishield/
├── main.py
├── detector/
│   ├── arp_detector.py
│   ├── gateway_monitor.py
│   ├── risk_engine.py
├── utils/
│   ├── logger.py
│   ├── network_utils.py
├── requirements.txt
└── README.md
```

## Installation

1. Create and activate a Python 3 virtual environment (recommended).
2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Run

From project directory:

```bash
python main.py
```

For Linux/macOS, run with root/admin privileges because packet sniffing and ARP inspection require elevated access:

```bash
sudo python main.py
```

Run simulation mode (no live sniffing, no root required):

```bash
python main.py --simulate
```

At startup, Wifishield will:

- detect your default gateway
- store its initial MAC address
- begin monitoring and show:
  - `Monitoring network for threats...`

In simulation mode, it generates realistic demo alerts using the same risk engine and logging pipeline.

## Alerts

Real-time alerts include:

- Attack Type (`ARP Spoofing` or `Gateway Attack`)
- IP Address
- MAC Address
- Risk Score
- Risk Level
- Reason

Also displays:

- `⚠️ Warning: Your network may be compromised. Consider disconnecting.`

If risk is high, Wifishield also suggests disconnecting from the network.

## Logs

All notable events are written to `logs.txt` with:

- timestamp
- event type
- risk score
- risk level
- details

## Lab Testing (Safe Environment Only)

Use only on networks you own or have explicit permission to test.

### Option A: Simulate with `arpspoof`

Install helper tools (example on Debian/Ubuntu):

```bash
sudo apt install dsniff
```

Run attack simulation from another test machine in the same lab network:

```bash
sudo arpspoof -i <interface> -t <victim_ip> <gateway_ip>
```

While simulation is running, Wifishield should report ARP conflicts and potentially gateway MAC anomalies.

### Option B: Generate ARP noise

Use any ARP scanner or scripted ARP traffic in a lab to trigger suspicious frequency counts.

## Limitations

- Works best on local/LAN networks where ARP is active.
- Detection quality depends on observed traffic volume.
- Requires root/admin privileges for sniffing.
- It is an anomaly detector, not a full intrusion prevention system.

## Disclaimer

Use this tool only for defensive security and authorized testing.
