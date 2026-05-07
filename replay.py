# Improvement #22 — Packet Replay from saved CSV
import csv
import time
import threading


def load_csv(filepath: str) -> list:
    """Loads a CSV capture log and returns a list of packet dicts."""
    packets = []
    try:
        with open(filepath, newline="") as f:
            for row in csv.DictReader(f):
                for field in ("size", "src_port", "dst_port"):
                    if field in row:
                        try:
                            row[field] = int(row[field])
                        except (ValueError, TypeError):
                            row[field] = 0
                packets.append(row)
    except Exception as e:
        print(f"Replay load error: {e}")
    return packets


def replay_into(packets: list, target_deque, lock, delay: float = 0.05):
    """
    Feeds packets into target_deque with a delay between each packet,
    simulating a live capture. Runs in a daemon thread.
    Returns the thread so callers can check .is_alive().
    """
    def _run():
        for pkt in packets:
            with lock:
                target_deque.append(pkt)
            time.sleep(delay)
        print(f"Replay complete — {len(packets)} packets injected.")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t
