import csv
from datetime import datetime

def export_to_csv(packets, filename=None):
    """
    Exports the captured packet list to a CSV file.
    Default timestamped filename: capture_log_YYYYMMDD_HHMMSS.csv
    """
    if not packets:
        print("Export failed: No packets captured yet.")
        return None
    
    if filename is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_log_{ts}.csv"
    
    keys = packets[0].keys()
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(packets)
        print(f"Exported {len(packets)} packets to {filename}")
        return filename
    except Exception as e:
        print(f"Export error: {e}")
        return None
