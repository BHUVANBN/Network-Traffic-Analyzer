# Improvement #19 — DNS Query Tracking
# dns_queries deque lives in capture.py; this module provides analysis helpers.

def get_top_domains(dns_queries, n=10):
    """Returns top N queried domain names with counts."""
    counts = {}
    for entry in dns_queries:
        d = entry.get("domain", "")
        if d:
            counts[d] = counts.get(d, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n])


def get_unique_requesters(dns_queries):
    """Returns list of unique source IPs that made DNS queries."""
    return list({e["src_ip"] for e in dns_queries if "src_ip" in e})
