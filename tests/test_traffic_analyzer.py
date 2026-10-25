
import unittest

from netsentinel.traffic_analyzer import (
    analyze_traffic,
    detect_port_scans,
    detect_high_traffic,
)


class TestTrafficAnalyzer(unittest.TestCase):
    def test_detects_port_scan(self):
        traffic = []

        for port in [21, 22, 23, 80, 443, 8080]:
            traffic.append({
                "src_ip": "192.0.2.50",
                "dst_ip": "198.51.100.50",
                "protocol": "TCP",
                "src_port": 52000 + port,
                "dst_port": port,
                "bytes": 60,
            })

        alerts = detect_port_scans(traffic)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "POTENTIAL_PORT_SCAN")
        self.assertEqual(alerts[0]["unique_ports"], 6)

    def test_ordinary_traffic_does_not_trigger_alert(self):
        traffic = [
            {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.20",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": 443,
                "bytes": 1450,
            },
            {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.20",
                "protocol": "TCP",
                "src_port": 50001,
                "dst_port": 443,
                "bytes": 1200,
            },
        ]

        alerts = detect_port_scans(traffic)

        self.assertEqual(alerts, [])

    def test_traffic_summary(self):
        traffic = [
            {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.20",
                "protocol": "TCP",
                "dst_port": 443,
                "bytes": 100,
            },
            {
                "src_ip": "192.0.2.11",
                "dst_ip": "198.51.100.30",
                "protocol": "UDP",
                "dst_port": 53,
                "bytes": 200,
            },
        ]

        summary = analyze_traffic(traffic)

        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["unique_source_ips"], 2)
        self.assertEqual(summary["total_bytes"], 300)


    def test_detects_high_traffic(self):
        traffic = [
            {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.10",
                "protocol": "TCP",
                "bytes": 3000,
            },
            {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.10",
                "protocol": "TCP",
                "bytes": 2500,
            },
        ]

        alerts = detect_high_traffic(traffic)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "HIGH_TRAFFIC_VOLUME")
        self.assertEqual(alerts[0]["total_bytes"], 5500)

    def test_low_traffic_does_not_trigger_alert(self):
        traffic = [
            {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.10",
                "protocol": "TCP",
                "bytes": 1000,
            },
        ]

        alerts = detect_high_traffic(traffic)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
