from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, conf
from scapy.arch import get_if_list
import threading
import time
import logging
import collections

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

MAX_PACKETS = 10000
captured_packets = collections.deque(maxlen=MAX_PACKETS)
_packets_lock    = threading.Lock()
is_capturing     = False

# Improvement #13 — DNS query tracking
dns_queries = collections.deque(maxlen=500)

# Improvement #13 — ICMP type labels
ICMP_TYPES = {
    0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
}


def get_interfaces():
    """Improvement #16 — returns available network interfaces for the selector."""
    try:
        return ["any"] + get_if_list()
    except Exception:
        return ["any"]


def process_packet(pkt):
    # Improvement #19 — DNS query tracking (UDP port 53)
    if IP in pkt and UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt and DNSQR in pkt:
        try:
            qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            with _packets_lock:
                dns_queries.append({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "src_ip":    pkt[IP].src,
                    "domain":    qname,
                })
        except Exception:
            pass

    entry = None

    if IP in pkt:
        # Improvement #17 — TCP flag parsing
        tcp_flags = ""
        if TCP in pkt:
            flag_map = {"S": "SYN", "A": "ACK", "F": "FIN",
                        "R": "RST", "P": "PSH", "U": "URG"}
            tcp_flags = " ".join(
                flag_map[f] for f in str(pkt[TCP].flags) if f in flag_map
            )

        # Improvement #13 — ICMP type label
        icmp_type = ""
        if ICMP in pkt:
            icmp_type = ICMP_TYPES.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")

        entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "src_ip":    pkt[IP].src,
            "dst_ip":    pkt[IP].dst,
            "protocol":  ("TCP"  if TCP  in pkt else
                          "UDP"  if UDP  in pkt else
                          "ICMP" if ICMP in pkt else "Other"),
            "size":      len(pkt),
            "src_port":  pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0,
            "dst_port":  pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0,
            "tcp_flags": tcp_flags,
            "icmp_type": icmp_type,
            "payload":   str(pkt[IP].payload)[:50],
        }
    elif ARP in pkt:
        entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "src_ip":    pkt[ARP].psrc,
            "dst_ip":    pkt[ARP].pdst,
            "protocol":  "ARP",
            "size":      len(pkt),
            "src_port":  0,
            "dst_port":  0,
            "tcp_flags": "",
            "icmp_type": "",
            "payload":   "",
        }

    if entry:
        with _packets_lock:
            captured_packets.append(entry)


def start_capture(iface=None, count=None):
    global is_capturing
    is_capturing = True
    print(f"Capture started on: {iface or 'default'}")
    kwargs = dict(prn=process_packet, store=False, timeout=2,
                  stop_filter=lambda x: not is_capturing)
    if iface and iface != "any":
        kwargs["iface"] = iface
    if count:
        kwargs["count"] = count
    while is_capturing:
        try:
            sniff(**kwargs)
        except Exception as e:
            print(f"Capture error: {e}")
            time.sleep(1)
    print("Capture stopped.")


def stop_capture():
    global is_capturing
    is_capturing = False


def start_capture_thread(iface=None):
    global is_capturing
    if is_capturing:
        return None
    is_capturing = True
    t = threading.Thread(target=start_capture, args=(iface,), daemon=True)
    t.start()
    return t
