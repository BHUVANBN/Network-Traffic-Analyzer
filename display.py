import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from capture import captured_packets, start_capture_thread, stop_capture, is_capturing
from analyzer import analyze_packets
from alert import detect_alerts
from exporter import export_to_csv
from geoip import get_ip_info
import time

# Custom Apple-Style Premium CSS
# -----------------------------
ST_PAGE_CONFIG = {
    "page_title": "Sentinel | Network Traffic Analyzer",
    "page_icon": "🛡️",
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
            --apple-orange: #FF9500;
            --glass-bg: rgba(28, 28, 30, 0.7);
            --border-color: rgba(255, 255, 255, 0.1);
        }

        /* Main Container */
        .stApp {
            background-color: #000000;
            color: #FFFFFF;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: rgba(28, 28, 30, 0.8) !important;
            backdrop-filter: blur(20px);
            border-right: 1px solid var(--border-color);
        }

        /* Premium Glass Card */
        .glass-card {
            background: var(--glass-bg);
            backdrop-filter: blur(25px) saturate(180%);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        /* Metrics Styling */
        [data-testid="stMetricValue"] {
            font-weight: 700 !important;
            font-size: 2.4rem !important;
            letter-spacing: -0.02em;
        }
        
        [data-testid="stMetricLabel"] {
            font-weight: 500 !important;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: rgba(255, 255, 255, 0.6) !important;
            font-size: 0.8rem !important;
        }

        /* Apple Buttons */
        .stButton>button {
            border-radius: 12px;
            background-color: #f5f5f7;
            color: #1d1d1f;
            border: none;
            padding: 12px 24px;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .stButton>button:hover {
            background-color: #ffffff;
            transform: scale(1.02);
        }

        .stButton>button:active {
            transform: scale(0.98);
        }

        /* Specialized Action Button (Start) */
        div[data-testid="column"]:nth-child(1) .stButton>button {
             background-color: var(--apple-blue);
             color: white;
        }

        /* Alert Styling */
        .alert-card {
            background: rgba(255, 59, 48, 0.1);
            border-left: 5px solid var(--apple-red);
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 12px;
            backdrop-filter: blur(10px);
        }

        .alert-title {
            color: var(--apple-red);
            font-weight: 700;
            font-size: 1.1rem;
            margin-bottom: 4px;
        }

        .alert-msg {
            color: #FFFFFF;
            font-weight: 400;
            opacity: 0.9;
        }

        /* Plotly Backgrounds */
        .js-plotly-plot .plotly .main-svg {
            background: transparent !important;
        }

        h1, h2, h3 {
            letter-spacing: -0.03em;
            font-weight: 700 !important;
        }
        </style>
    """, unsafe_allow_html=True)

# Main Application Logic
# ----------------------
def show_dashboard():
    st.set_page_config(**ST_PAGE_CONFIG)
    inject_custom_css()

    # Header with Apple Vibe
    st.markdown("""
        <div style="margin-top: -50px; margin-bottom: 40px;">
            <p style="color: #007AFF; font-weight: 600; margin-bottom: 0;">NETWORK FORENSICS</p>
            <h1 style="font-size: 3.5rem; margin-top: 0;">Sentinel Analyzer</h1>
            <p style="opacity: 0.6; font-size: 1.1rem;">Professional real-time traffic monitoring & security auditing.</p>
        </div>
    """, unsafe_allow_html=True)

    # Sidebar Controls
    # ----------------
    with st.sidebar:
        st.markdown("<h2 style='font-size: 1.5rem;'>Dashboard</h2>", unsafe_allow_html=True)
        st.write("---")
        
        status_color = "🟢" if is_capturing else "⚪"
        st.markdown(f"**Capture Status**: {status_color} {('Active' if is_capturing else 'Idle')}")
        
        if not is_capturing:
            if st.button("🚀 Start Live Capture", use_container_width=True):
                start_capture_thread()
                st.rerun()
        else:
            if st.button("🛑 Stop Live Capture", use_container_width=True):
                stop_capture()
                st.rerun()
        
        st.write("---")
        if st.button("📂 Export Current Logs", use_container_width=True):
            f = export_to_csv(captured_packets)
            if f: st.success(f"Saved: {f}")
        
        if st.button("🗑️ Reset Session", use_container_width=True):
            captured_packets.clear()
            st.rerun()
        
        st.write("---")
        st.caption("v1.0.0")

    # Analyzier Execution
    # -------------------
    df, summary, proto_dist = analyze_packets(captured_packets)

    if df.empty:
        st.markdown("""
            <div class="glass-card" style="text-align: center; padding: 100px;">
                <h2 style="opacity: 0.8;">Ready for Analysis</h2>
                <p style="opacity: 0.5;">Click 'Start Live Capture' in the sidebar to begin monitoring your interface.</p>
            </div>
        """, unsafe_allow_html=True)
        if is_capturing:
            time.sleep(2)
            st.rerun()
        return

    # Metrics Layout (Apple Health style)
    # -----------------------------------
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Packets", summary['total'])
    with m2:
        st.metric("TCP Stream", summary['tcp'])
    with m3:
        st.metric("UDP Datagrams", summary['udp'])
    with m4:
        st.metric("Data Captured", summary['total_size'])

    # Charts Section
    # --------------
    st.write("---")
    c1, c2 = st.columns(2)
    
    with c1:
        st.markdown("<h3 style='margin-bottom: 25px;'>Protocol Analytics</h3>", unsafe_allow_html=True)
        colors = ['#007AFF', '#5856D6', '#FF2D55', '#AF52DE', '#FF9500']
        fig_pie = px.pie(
            values=list(proto_dist.values()), 
            names=list(proto_dist.keys()),
            hole=0.7,
            color_discrete_sequence=colors
        )
        fig_pie.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', 
            plot_bgcolor='rgba(0,0,0,0)', 
            font_color='white',
            margin=dict(t=0, b=0, l=0, r=0),
            showlegend=True
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with c2:
        st.markdown("<h3 style='margin-bottom: 25px;'>Top Talkers (Source)</h3>", unsafe_allow_html=True)
        if summary['top_src']:
            top_src_df = pd.DataFrame(list(summary['top_src'].items()), columns=['IP', 'Count'])
            fig_bar = px.bar(
                top_src_df, x='IP', y='Count', 
                color='Count', 
                color_continuous_scale=['#1C1C1E', '#007AFF'],
                labels={'IP': 'Source Address', 'Count': 'Packets'}
            )
            fig_bar.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)', 
                font_color='white',
                margin=dict(t=0, b=0, l=0, r=0),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.write("No source IP data yet.")

    # Alerts Section
    # --------------
    alerts = detect_alerts(df)
    if alerts:
        st.write("---")
        st.markdown("<h3 style='color: #FF3B30;'>Security Threats</h3>", unsafe_allow_html=True)
        for a in alerts:
            st.markdown(f"""
                <div class="alert-card">
                    <div class="alert-title">{a['type']} DETECTED</div>
                    <div class="alert-msg">{a['message']} – Severity: {a['severity']}</div>
                </div>
            """, unsafe_allow_html=True)

    # Detailed Packet Table
    # ---------------------
    st.write("---")
    st.subheader("Traffic History")
    # Styling dataframe for dark mode
    st.dataframe(df, use_container_width=True)

    # Auto-refresh mechanism
    if is_capturing:
        time.sleep(3)
        st.rerun()

if __name__ == "__main__":
    show_dashboard()


if __name__ == "__main__":
    show_dashboard()
