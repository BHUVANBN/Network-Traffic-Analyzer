import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import capture
from analyzer import analyze_packets
from alert import detect_alerts
from exporter import export_to_csv
from geoip import get_ip_info
import time

# Custom Professional UI Assets (SVG Icons)
# ----------------------------------------
ICONS = {
    "shield": '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 8px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "activity": '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 8px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    "download": '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 8px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    "trash": '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 8px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>',
    "alert": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 8px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
}

# Custom Apple-Style Premium CSS
# -----------------------------
ST_PAGE_CONFIG = {
    "page_title": "Sentinel | Network Traffic Analyzer",
    "layout": "wide",
}

def inject_custom_css():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
        
        :root {
            --apple-blue: #007AFF;
            --apple-green: #34C759;
            --apple-red: #FF3B30;
            --glass-bg: rgba(20, 20, 22, 0.85);
            --border-color: rgba(255, 255, 255, 0.08);
        }

        .stApp {
            background-color: #000000;
            color: #FFFFFF;
            font-family: 'Inter', -apple-system, sans-serif;
        }

        /* Status Pill */
        .status-pill {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 100px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .status-active { background: rgba(52, 199, 89, 0.15); color: #34C759; border: 1px solid rgba(52, 199, 89, 0.2); }
        .status-idle { background: rgba(255, 255, 255, 0.05); color: rgba(255, 255, 255, 0.5); border: 1px solid var(--border-color); }
        .status-dot { width: 6px; height: 6px; border-radius: 50%; margin-right: 8px; }
        .dot-active { background: #34C759; box-shadow: 0 0 8px #34C759; }
        .dot-idle { background: rgba(255, 255, 255, 0.3); }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: #0A0A0B !important;
            border-right: 1px solid var(--border-color);
        }

        /* Glass Cards */
        .glass-card {
            background: var(--glass-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 24px;
        }

        .alert-card {
            background: rgba(255, 59, 48, 0.08);
            border: 1px solid rgba(255, 59, 48, 0.15);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
        }

        h1, h2, h3 { letter-spacing: -0.03em; }
        
        /* Metric Styling Override */
        [data-testid="stMetricValue"] { font-size: 2.2rem !important; }
        [data-testid="stMetricLabel"] { opacity: 0.5 !important; font-size: 0.75rem !important; }

        /* Plotly */
        .js-plotly-plot .plotly .main-svg { background: transparent !important; }
        </style>
    """, unsafe_allow_html=True)

# Main Application Logic
# ----------------------
def show_dashboard():
    st.set_page_config(**ST_PAGE_CONFIG)
    inject_custom_css()

    # AUTO-START CAPTURE ON FIRST LOAD
    # --------------------------------
    if not capture.is_capturing:
        capture.start_capture_thread()
        # Small delay to allow the thread to initialize
        time.sleep(0.5)

    header_html = f"""
        <div style="margin-top: -50px; margin-bottom: 40px; display: flex; align-items: baseline; gap: 15px;">
            <div style="background: var(--apple-blue); padding: 10px; border-radius: 12px; color: white;">
                {ICONS['shield']}
            </div>
            <div>
                <h1 style="font-size: 2.8rem; margin: 0; font-weight: 700;">Sentinel</h1>
                <p style="opacity: 0.5; font-size: 0.9rem; margin-top: 4px;">SYSTEM NETWORK ANALYZER • ENTERPRISE CORE</p>
            </div>
        </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)

    # Sidebar Controls
    # ----------------
    with st.sidebar:
        st.markdown("<p style='font-size: 0.7rem; font-weight: 700; opacity: 0.4; letter-spacing: 0.1em; margin-bottom: 20px;'>CONTROL INTERFACE</p>", unsafe_allow_html=True)
        
        status_pill = f"""
            <div class="status-pill status-{'active' if capture.is_capturing else 'idle'}">
                <div class="status-dot dot-{'active' if capture.is_capturing else 'idle'}"></div>
                {'Live Interface' if capture.is_capturing else 'Sniffing Suspended'}
            </div>
        """
        st.markdown(status_pill, unsafe_allow_html=True)
        st.write("")

        # Clean Sidebar: Move controls to Advanced section
        with st.expander("ADVANCED CONTROLS"):
            if capture.is_capturing:
                if st.button("TERMINATE INTERFACE", width="stretch"):
                    capture.stop_capture()
                    st.rerun()
            else:
                if st.button("RE-INITIALIZE INTERFACE", width="stretch"):
                    capture.start_capture_thread()
                    st.rerun()
        
        st.write("---")
        
        if st.button("DOWNLOAD CSV REPORT", width="stretch"):
            f = export_to_csv(capture.captured_packets)
            if f: st.success(f"Log generated: {f}")
        
        if st.button("RESET SESSION DATA", width="stretch"):
            capture.captured_packets.clear()
            st.rerun()
        
        st.write("---")
        st.caption("FIRMWARE V1.0.0-PRO")

    # Data Analytics Engine
    # ---------------------------
    df, summary, proto_dist = analyze_packets(capture.captured_packets)

    if df.empty:
        st.markdown("""
            <div class="glass-card" style="text-align: center; padding: 120px 20px;">
                <div style="opacity: 0.2; margin-bottom: 20px;">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                </div>
                <h3 style="opacity: 0.6; font-weight: 400;">Sniffing Engine Initializing...</h3>
                <p style="opacity: 0.4; font-size: 0.9rem;">Waiting for incoming traffic to be analyzed.</p>
            </div>
        """, unsafe_allow_html=True)
    else:
        # Metrics Layout
        m1, m2, m3, m4 = st.columns(4)
        with m1: st.metric("INGESTED PACKETS", summary['total'])
        with m2: st.metric("TCP TRAFFIC", summary['tcp'])
        with m3: st.metric("UDP TRAFFIC", summary['udp'])
        with m4: st.metric("THROUGHPUT", summary['total_size'])

        # Charts Section
        st.write("---")
        c1, c2 = st.columns([2, 3])
        
        with c1:
            st.markdown(f"<div style='display: flex; align-items: center;'>{ICONS['activity']} <h3 style='margin: 0;'>Protocol Mix</h3></div>", unsafe_allow_html=True)
            st.write("")
            colors = ['#007AFF', '#5E5CE6', '#FF2D55', '#AF52DE', '#FF9500']
            fig_pie = px.pie(
                values=list(proto_dist.values()), 
                names=list(proto_dist.keys()),
                hole=0.8,
                color_discrete_sequence=colors
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', 
                font_color='white', margin=dict(t=0, b=0, l=0, r=0),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_pie, width="stretch")

        with c2:
            st.markdown(f"<div style='display: flex; align-items: center;'>{ICONS['activity']} <h3 style='margin: 0;'>Origin Analysis</h3></div>", unsafe_allow_html=True)
            st.write("")
            if summary['top_src']:
                top_src_df = pd.DataFrame(list(summary['top_src'].items()), columns=['IP', 'Count'])
                fig_bar = px.bar(
                    top_src_df, x='IP', y='Count', 
                    color_discrete_sequence=['#007AFF'],
                    labels={'IP': 'Address', 'Count': 'Packets'}
                )
                fig_bar.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', 
                    font_color='white', margin=dict(t=0, b=10, l=0, r=0),
                    xaxis_title=None, yaxis_title=None
                )
                st.plotly_chart(fig_bar, width="stretch")

        # Alerts Section
        alerts = detect_alerts(df)
        if alerts:
            st.write("---")
            st.markdown(f"<div style='display: flex; align-items: center; color: var(--apple-red);'>{ICONS['alert']} <h3 style='margin: 0;'>Threat Intelligence</h3></div>", unsafe_allow_html=True)
            st.write("")
            for a in alerts:
                st.markdown(f"""
                    <div class="alert-card">
                        <div style="font-weight: 700; color: var(--apple-red); letter-spacing: 0.1em; font-size: 0.75rem; margin-bottom: 8px;">{a['type'].upper()} ALERT</div>
                        <div style="font-size: 1rem; opacity: 0.9;">{a['message']}</div>
                    </div>
                """, unsafe_allow_html=True)

        # Detailed Packet Table
        st.write("---")
        st.markdown("<p style='font-size: 0.75rem; font-weight: 700; opacity: 0.4; letter-spacing: 0.1em; margin-bottom: 12px;'>INGESTION LOG</p>", unsafe_allow_html=True)
        st.dataframe(df.tail(15), width="stretch")

    # AUTO-REFRESH TRIGGER (Non-blocking pulse)
    if capture.is_capturing:
        time.sleep(1)
        st.rerun()

if __name__ == "__main__":
    show_dashboard()
