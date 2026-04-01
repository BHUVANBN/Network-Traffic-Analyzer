import pandas as pd

def analyze_packets(packets):
    """
    Groups and summarizes captured packets into statistics.
    Returns: DataFrame, summary dict, and protocol distribution dict.
    """
    if not packets:
        return pd.DataFrame(), {}, {}
        
    # Thread-safe snapshot to avoid list mutation during DataFrame creation
    packets_snapshot = list(packets)
    df = pd.DataFrame(packets_snapshot)
    
    if df.empty:
        return df, {}, {}

    summary = {
        "total":    len(df),
        "tcp":      len(df[df["protocol"] == "TCP"]),
        "udp":      len(df[df["protocol"] == "UDP"]),
        "icmp":     len(df[df["protocol"] == "ICMP"]),
        "other":    len(df[df["protocol"] == "Other"]),
        "top_src":  df["src_ip"].value_counts().head(5).to_dict(),
        "top_dst":  df["dst_ip"].value_counts().head(5).to_dict(),
        "total_size": f"{df['size'].sum() / 1024:.2f} KB"
    }
    
    protocol_dist = df['protocol'].value_counts().to_dict()
    
    return df, summary, protocol_dist
