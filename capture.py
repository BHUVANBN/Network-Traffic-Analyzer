from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import threading
import time

# List to store captured packets in memory
captured_packets = []
# Flag to control the capture loop
is_capturing = False

def process_packet(pkt):
    if IP in pkt:
        entry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "src_ip":   pkt[IP].src,
            "dst_ip":   pkt[IP].dst,
            "protocol": "TCP"  if TCP  in pkt else
                        "UDP"  if UDP  in pkt else
                        "ICMP" if ICMP in pkt else "Other",
            "size":     len(pkt),
            "dst_port": pkt[TCP].dport if TCP in pkt else
                        pkt[UDP].dport if UDP in pkt else 0,
            "payload":  str(pkt[IP].payload)[:50] # Snippet for deeper analysis
        }
        captured_packets.append(entry)

def start_capture(count=None):
    global is_capturing
    is_capturing = True
    # count=None means it will run until stopped
    try:
        sniff(prn=process_packet, count=count, stop_filter=lambda x: not is_capturing, store=False)
    except Exception as e:
        print(f"Capture error: {e}")
        is_capturing = False

def stop_capture():
    global is_capturing
    is_capturing = False

def start_capture_thread():
    t = threading.Thread(target=start_capture, daemon=True)
    t.start()
    return t
