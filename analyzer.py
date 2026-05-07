import pandas as pd


def analyze_packets(packets):
    """Core analysis — returns (df, summary, protocol_dist)."""
    if not packets:
        return pd.DataFrame(), {}, {}

    snapshot = list(packets)
    df = pd.DataFrame(snapshot)
    if df.empty:
        return df, {}, {}

    summary = {
        "total":      len(df),
        "tcp":        len(df[df["protocol"] == "TCP"]),
        "udp":        len(df[df["protocol"] == "UDP"]),
        "icmp":       len(df[df["protocol"] == "ICMP"]),
        "arp":        len(df[df["protocol"] == "ARP"]),
        "other":      len(df[df["protocol"] == "Other"]),
        "top_src":    df["src_ip"].value_counts().head(5).to_dict(),
        "top_dst":    df["dst_ip"].value_counts().head(5).to_dict(),
        "total_size": f"{df['size'].sum() / 1024:.2f} KB",
        "unique_src": int(df["src_ip"].nunique()),
        "unique_dst": int(df["dst_ip"].nunique()),
    }
    protocol_dist = df["protocol"].value_counts().to_dict()
    return df, summary, protocol_dist


def get_time_series(df):
    """Improvement #15 — packets per timestamp for the traffic line chart."""
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame()
    return df.groupby("timestamp").size().reset_index(name="count")


def get_size_distribution(df):
    """Improvement #14 — bucket packets into Small / Medium / Large."""
    if df.empty or "size" not in df.columns:
        return {}
    buckets = {"Small\n<100 B": 0, "Medium\n100–1000 B": 0, "Large\n>1000 B": 0}
    for sz in df["size"]:
        if sz < 100:
            buckets["Small\n<100 B"] += 1
        elif sz <= 1000:
            buckets["Medium\n100–1000 B"] += 1
        else:
            buckets["Large\n>1000 B"] += 1
    return buckets


def get_tcp_flag_counts(df):
    """Improvement #17 — count packets containing each TCP flag."""
    if df.empty or "tcp_flags" not in df.columns:
        return {}
    tcp_df = df[(df["protocol"] == "TCP") & (df["tcp_flags"] != "")]
    if tcp_df.empty:
        return {}
    flags = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]
    return {f: int(tcp_df["tcp_flags"].str.contains(f).sum())
            for f in flags if tcp_df["tcp_flags"].str.contains(f).any()}


def get_icmp_breakdown(df):
    """Improvement #13 — ICMP message type distribution."""
    if df.empty or "icmp_type" not in df.columns:
        return {}
    icmp_df = df[(df["protocol"] == "ICMP") & (df["icmp_type"] != "")]
    if icmp_df.empty:
        return {}
    return icmp_df["icmp_type"].value_counts().to_dict()
