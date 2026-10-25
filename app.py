
import streamlit as st
import pandas as pd

from netsentinel.traffic_analyzer import (
    analyze_traffic,
    detect_port_scans,
    detect_repeated_connections,
    detect_high_traffic,
    load_traffic,
)

st.set_page_config(
    page_title="NetSentinel | Threat Monitor",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ NetSentinel")
st.subheader("Network Intrusion Detection & Threat Monitoring")
st.caption("Portfolio project • Simulated traffic analysis")

# Load the sample traffic.
traffic = load_traffic()

# Add clearly labeled simulated scan activity for the demo.
demo_scan = []


# Add simulated repeated TCP events for demonstration.
demo_repeated = []

for attempt in range(12):
    demo_repeated.append({
        "timestamp": "2026-10-25T08:02:00Z",
        "src_ip": "192.0.2.60",
        "dst_ip": "198.51.100.60",
        "protocol": "TCP",
        "src_port": 53000 + attempt,
        "dst_port": 443,
        "bytes": 100,
    })


for port in [21, 22, 23, 80, 443, 8080]:
    demo_scan.append({
        "timestamp": "2026-10-25T08:01:00Z",
        "src_ip": "192.0.2.50",
        "dst_ip": "198.51.100.50",
        "protocol": "TCP",
        "src_port": 52000 + port,
        "dst_port": port,
        "bytes": 60,
    })


demo_high_traffic = []

for attempt in range(12):
    demo_high_traffic.append({
        "timestamp": "2026-10-25T08:03:00Z",
        "src_ip": "192.0.2.70",
        "dst_ip": "198.51.100.70",
        "protocol": "TCP",
        "src_port": 54000 + attempt,
        "dst_port": 443,
        "bytes": 600,
    })

all_traffic = traffic + demo_scan + demo_repeated + demo_high_traffic


summary = analyze_traffic(all_traffic)

port_scan_alerts = detect_port_scans(all_traffic)
repeated_connection_alerts = detect_repeated_connections(all_traffic)
high_traffic_alerts = detect_high_traffic(all_traffic)

alerts = (
    port_scan_alerts
    + repeated_connection_alerts
    + high_traffic_alerts
)

# Main metrics.
col1, col2, col3, col4 = st.columns(4)

col1.metric("Traffic Events", summary["total_events"])
col2.metric("Source IPs", summary["unique_source_ips"])
col3.metric("Destination IPs", summary["unique_destination_ips"])
col4.metric("Security Alerts", len(alerts))

st.divider()

# Traffic protocol summary.
left, right = st.columns(2)

with left:
    st.subheader("📊 Protocol Distribution")

    protocol_data = pd.DataFrame(
        list(summary["protocol_counts"].items()),
        columns=["Protocol", "Events"],
    )

    st.bar_chart(protocol_data, x="Protocol", y="Events")
    st.dataframe(protocol_data, hide_index=True, use_container_width=True)


with right:
    st.subheader("🚨 Security Alerts")

    if alerts:
        for alert in alerts:
            details = []

            if "ports_observed" in alert:
                details.append(
                    f"Ports observed: {alert['ports_observed']}"
                )

            if "attempts" in alert:
                details.append(
                    f"TCP events counted: {alert['attempts']}"
                )

            st.warning(
                f"**{alert['type']}** — "
                f"{alert['severity'].upper()}\n\n"
                f"{alert['message']}"
            )

            if details:
                st.caption(" | ".join(details))
    else:
        st.success("No suspicious activity detected.")

st.divider()


# Interactive traffic filters.
st.subheader("🔎 Traffic Event Log")
st.caption("Filter events to investigate network activity.")

traffic_df = pd.DataFrame(all_traffic)

# Mark events that match a detected port-scan alert.
scan_sources = {
    (alert["source_ip"], alert["destination_ip"])
    for alert in alerts
}

traffic_df["Suspicious"] = traffic_df.apply(
    lambda row: (
        row["src_ip"],
        row["dst_ip"],
    ) in scan_sources,
    axis=1,
)

filter1, filter2, filter3 = st.columns(3)

with filter1:
    selected_protocols = st.multiselect(
        "Protocol",
        options=sorted(traffic_df["protocol"].unique()),
        default=sorted(traffic_df["protocol"].unique()),
    )

with filter2:
    selected_sources = st.multiselect(
        "Source IP",
        options=sorted(traffic_df["src_ip"].unique()),
        default=[],
        placeholder="All source IPs",
    )

with filter3:
    suspicious_only = st.checkbox(
        "Show suspicious traffic only",
        value=False,
    )

filtered_df = traffic_df[
    traffic_df["protocol"].isin(selected_protocols)
]

if selected_sources:
    filtered_df = filtered_df[
        filtered_df["src_ip"].isin(selected_sources)
    ]

if suspicious_only:
    filtered_df = filtered_df[
        filtered_df["Suspicious"]
    ]

st.metric("Events matching filters", len(filtered_df))

st.dataframe(
    filtered_df,
    hide_index=True,
    use_container_width=True,
)


st.caption(
    "Demo mode: all traffic is simulated. "
    "This dashboard does not capture live network packets."
)
