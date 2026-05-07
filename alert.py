def detect_alerts(df, port_scan_threshold=10, flood_threshold=100, syn_flood_threshold=50):
    """
    Improvement #12 — thresholds are now parameters (fed from UI sliders).
    Improvement #17 — added SYN flood detection via TCP flags.
    """
    alerts = []
    if df.empty:
        return alerts

    # Port scan: one source hitting many unique destination ports
    if "dst_port" in df.columns:
        port_scan = (
            df[df["protocol"] == "TCP"]
            .groupby("src_ip")["dst_port"]
            .nunique()
        )
        for ip, count in port_scan.items():
            if count > port_scan_threshold:
                alerts.append({
                    "type":     "PORT SCAN",
                    "message":  f"{ip} scanned {count} unique ports",
                    "severity": "High",
                })

    # Flood: single source sending massive packet counts
    flood = df["src_ip"].value_counts()
    for ip, count in flood.items():
        if count > flood_threshold:
            alerts.append({
                "type":     "FLOOD",
                "message":  f"{ip} sent {count} packets in capture period",
                "severity": "Medium",
            })

    # SYN flood: many pure-SYN packets (half-open connection attack)
    if "tcp_flags" in df.columns:
        syn_only = df[(df["protocol"] == "TCP") & (df["tcp_flags"] == "SYN")]
        syn_counts = syn_only["src_ip"].value_counts()
        for ip, count in syn_counts.items():
            if count > syn_flood_threshold:
                alerts.append({
                    "type":     "SYN FLOOD",
                    "message":  f"{ip} sent {count} bare SYN packets — possible half-open attack",
                    "severity": "High",
                })

    return alerts
