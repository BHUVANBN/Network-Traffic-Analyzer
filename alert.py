def detect_alerts(df):
    """
    Scans the packet DataFrame for suspicious patterns.
    - Port Scans (Many unique destination ports from one source IP)
    - Flooding (High packet count from one source IP)
    """
    alerts = []
    if df.empty:
        return alerts

    # Thresold values: can be adjusted for sensitivity
    PORT_SCAN_THRESHOLD = 10
    FLOOD_THRESHOLD = 100

    # Detect Port Scan: same src IP hitting many different ports (focus on TCP)
    port_scan = (
        df[df["protocol"] == "TCP"]
        .groupby("src_ip")["dst_port"]
        .nunique()
    )
    for ip, count in port_scan.items():
        if count > PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT SCAN",
                "message": f"{ip} scanned {count} unique ports",
                "severity": "High"
            })

    # Detect Flooding: single IP sending huge number of packets
    flood = df["src_ip"].value_counts()
    for ip, count in flood.items():
        if count > FLOOD_THRESHOLD:
            alerts.append({
                "type": "FLOOD",
                "message": f"{ip} sent {count} packets in capture period",
                "severity": "Medium"
            })

    return alerts
