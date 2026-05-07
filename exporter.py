import csv
import io
from datetime import datetime

# Fix #6: Use Matplotlib to generate a companion protocol chart on CSV export
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend — safe for server/thread environments
import matplotlib.pyplot as plt


def export_to_csv(packets, filename=None):
    """
    Exports the captured packet list to a timestamped CSV file.
    Also generates a companion protocol distribution PNG chart via Matplotlib.
    """
    if not packets:
        print("Export failed: No packets captured yet.")
        return None

    if filename is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"capture_log_{ts}.csv"

    packets_list = list(packets)
    keys = packets_list[0].keys()

    try:
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(packets_list)
        print(f"Exported {len(packets_list)} packets to {filename}")

        # Generate a companion static chart using Matplotlib
        chart_file = filename.replace(".csv", "_chart.png")
        _export_protocol_chart(packets_list, chart_file)

        return filename
    except Exception as e:
        print(f"Export error: {e}")
        return None


def get_csv_bytes(packets):
    """
    Returns CSV content as UTF-8 bytes for Streamlit's st.download_button.
    No file is written to disk — fully in-memory.
    """
    if not packets:
        return None

    packets_list = list(packets)
    output = io.StringIO()
    keys = packets_list[0].keys()
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    writer.writerows(packets_list)
    return output.getvalue().encode("utf-8")


def _export_protocol_chart(packets_list, chart_filename):
    """
    Uses Matplotlib to save a static protocol distribution pie chart as PNG.
    Runs silently — errors are caught to avoid interrupting the export flow.
    """
    try:
        protocols = {}
        for pkt in packets_list:
            proto = pkt.get("protocol", "Other")
            protocols[proto] = protocols.get(proto, 0) + 1

        if not protocols:
            return

        colors = ["#007AFF", "#5E5CE6", "#FF2D55", "#AF52DE", "#FF9500", "#34C759"]
        fig, ax = plt.subplots(figsize=(6, 4))
        fig.patch.set_facecolor("#0D0D0F")
        ax.set_facecolor("#0D0D0F")

        wedges, texts, autotexts = ax.pie(
            list(protocols.values()),
            labels=list(protocols.keys()),
            colors=colors[: len(protocols)],
            autopct="%1.1f%%",
            startangle=90,
        )
        for text in texts + autotexts:
            text.set_color("white")

        ax.set_title("Protocol Distribution", color="white", fontsize=13, fontweight="bold")
        plt.tight_layout()
        plt.savefig(chart_filename, dpi=100, bbox_inches="tight", facecolor="#0D0D0F")
        plt.close(fig)
        print(f"Chart saved to {chart_filename}")
    except Exception as e:
        print(f"Chart export error: {e}")
