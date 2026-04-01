from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, conf
import threading
import time
import logging

# Silence Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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
    print("Background capture thread started...")
    
    # Use a loop to keep sniffing continuously even after timeouts
    while is_capturing:
        try:
            # Short timeout allows periodic checks of 'is_capturing' flag
            sniff(prn=process_packet, count=count, stop_filter=lambda x: not is_capturing, store=False, timeout=2)
        except Exception as e:
            print(f"Capture error: {e}")
            # Optional: pause briefly on error before retrying
            time.sleep(1)
    
    print("Background capture thread stopped.")

def stop_capture():
    global is_capturing
    is_capturing = False

def start_capture_thread():
    global is_capturing
    if is_capturing:
        return None
    is_capturing = True
    t = threading.Thread(target=start_capture, daemon=True)
    t.start()
    return t
