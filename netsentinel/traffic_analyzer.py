
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "data" / "sample_traffic.json"


def load_traffic():
    """Load simulated network traffic from a JSON file."""
    with DATA_FILE.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("Traffic data must be a JSON list.")

    return records


def detect_port_scans(records, min_unique_ports=5):
    """Flag sources probing multiple ports on the same destination."""
    probes = {}

    for record in records:
        if record["protocol"].upper() not in {"TCP", "UDP"}:
            continue

        destination_port = record.get("dst_port")

        if destination_port is None:
            continue

        key = (record["src_ip"], record["dst_ip"])
        probes.setdefault(key, set()).add(destination_port)

    alerts = []

    for (source_ip, destination_ip), ports in probes.items():
        if len(ports) >= min_unique_ports:
            alerts.append({
                "type": "POTENTIAL_PORT_SCAN",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "unique_ports": len(ports),
                "ports_observed": sorted(ports),
                "message": (
                    f"Source {source_ip} contacted "
                    f"{len(ports)} unique ports on {destination_ip}."
                ),
            })

    return alerts


def detect_repeated_connections(records, min_attempts=10):
    """Flag source/destination pairs with many TCP events."""
    attempts = {}

    for record in records:
        if record["protocol"].upper() != "TCP":
            continue

        key = (record["src_ip"], record["dst_ip"])
        attempts[key] = attempts.get(key, 0) + 1

    alerts = []

    for (source_ip, destination_ip), count in attempts.items():
        if count >= min_attempts:
            alerts.append({
                "type": "REPEATED_CONNECTION_ATTEMPTS",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "attempts": count,
                "message": (
                    f"Source {source_ip} generated {count} TCP "
                    f"events to {destination_ip}."
                ),
            })

    return alerts


def detect_high_traffic(records, min_bytes=5000):
    """Flag source/destination pairs with high total traffic."""
    traffic_totals = {}

    for record in records:
        key = (record["src_ip"], record["dst_ip"])
        traffic_totals[key] = (
            traffic_totals.get(key, 0) + record["bytes"]
        )

    alerts = []

    for (source_ip, destination_ip), total_bytes in traffic_totals.items():
        if total_bytes >= min_bytes:
            alerts.append({
                "type": "HIGH_TRAFFIC_VOLUME",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "total_bytes": total_bytes,
                "message": (
                    f"Source {source_ip} transferred "
                    f"{total_bytes} bytes to {destination_ip}."
                ),
            })

    return alerts


def analyze_traffic(records):
    """Calculate basic statistics from simulated traffic."""
    protocol_counts = Counter()
    source_ips = set()
    destination_ips = set()
    total_bytes = 0

    for record in records:
        protocol_counts[record["protocol"].upper()] += 1
        source_ips.add(record["src_ip"])
        destination_ips.add(record["dst_ip"])
        total_bytes += record["bytes"]

    return {
        "total_events": len(records),
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "total_bytes": total_bytes,
        "protocol_counts": dict(sorted(protocol_counts.items())),
    }


if __name__ == "__main__":
    traffic = load_traffic()

    print("TRAFFIC SUMMARY")
    report = analyze_traffic(traffic)
    print(json.dumps(report, indent=2))

    # Simulated port-scan traffic for demonstration only.
    simulated_scan = []

    for port in [21, 22, 23, 80, 443, 8080]:
        simulated_scan.append({
            "timestamp": "2026-10-25T08:01:00Z",
            "src_ip": "192.0.2.50",
            "dst_ip": "198.51.100.50",
            "protocol": "TCP",
            "src_port": 52000 + port,
            "dst_port": port,
            "bytes": 60,
        })

    # Simulated repeated TCP events for demonstration only.
    simulated_repeated = []

    for attempt in range(12):
        simulated_repeated.append({
            "timestamp": "2026-10-25T08:02:00Z",
            "src_ip": "192.0.2.60",
            "dst_ip": "198.51.100.60",
            "protocol": "TCP",
            "src_port": 53000 + attempt,
            "dst_port": 443,
            "bytes": 100,
        })

    test_traffic = traffic + simulated_scan + simulated_repeated

    print("\nPORT-SCAN ALERTS")
    print(json.dumps(detect_port_scans(test_traffic), indent=2))

    print("\nREPEATED-CONNECTION ALERTS")
    print(
        json.dumps(
            detect_repeated_connections(test_traffic),
            indent=2,
        )
    )
