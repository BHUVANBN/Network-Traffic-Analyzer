import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import datetime, time, io

import capture
from analyzer import (analyze_packets, get_time_series,
                      get_size_distribution, get_tcp_flag_counts, get_icmp_breakdown)
from alert import detect_alerts
from exporter import get_csv_bytes
from geoip import get_ip_info, get_ip_coords, get_hostname
from dns_tracker import get_top_domains
from notifier import send_email_alert, reset_notifications
import replay as replay_mod

# ── try folium (optional) ─────────────────────────────────────────────────────
try:
    import folium
    from streamlit_folium import st_folium
    HAS_FOLIUM = True
except ImportError:
    HAS_FOLIUM = False

SEVERITY_STYLE = {
    "High":   {"bg":"rgba(255,59,48,.08)",  "border":"rgba(255,59,48,.3)",  "color":"#FF3B30","badge":"rgba(255,59,48,.25)"},
    "Medium": {"bg":"rgba(255,149,0,.08)",  "border":"rgba(255,149,0,.3)",  "color":"#FF9500","badge":"rgba(255,149,0,.25)"},
    "Low":    {"bg":"rgba(255,214,10,.08)", "border":"rgba(255,214,10,.3)", "color":"#FFD60A","badge":"rgba(255,214,10,.25)"},
}
COLORS = ["#007AFF","#5E5CE6","#FF2D55","#AF52DE","#FF9500","#34C759"]
CHART_LAYOUT = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="white", margin=dict(t=10,b=10,l=0,r=0))

LIGHT_BG  = "#F2F2F7"; LIGHT_CARD = "rgba(255,255,255,0.9)"; LIGHT_TEXT = "#1C1C1E"
DARK_BG   = "#000000"; DARK_CARD  = "rgba(20,20,22,0.85)";   DARK_TEXT  = "#FFFFFF"


def _css(theme):
    bg    = LIGHT_BG   if theme=="Light" else DARK_BG
    card  = LIGHT_CARD if theme=="Light" else DARK_CARD
    txt   = LIGHT_TEXT if theme=="Light" else DARK_TEXT
    side  = "#FFFFFF"  if theme=="Light" else "#0A0A0B"
    st.markdown(f"""<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    :root{{--blue:#007AFF;--green:#34C759;--red:#FF3B30;--border:rgba(128,128,128,.12);}}
    .stApp{{background:{bg};color:{txt};font-family:'Inter',-apple-system,sans-serif;}}
    section[data-testid="stSidebar"]{{background-color:{side}!important;border-right:1px solid var(--border);}}
    .kard{{background:{card};border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:16px;}}
    .pill{{display:inline-flex;align-items:center;padding:4px 12px;border-radius:100px;
           font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;}}
    .pill-on{{background:rgba(52,199,89,.15);color:#34C759;border:1px solid rgba(52,199,89,.25);}}
    .pill-off{{background:rgba(128,128,128,.1);color:rgba(128,128,128,.8);border:1px solid var(--border);}}
    .dot{{width:6px;height:6px;border-radius:50%;margin-right:8px;display:inline-block;}}
    .dot-on{{background:#34C759;box-shadow:0 0 8px #34C759;}}
    .dot-off{{background:rgba(128,128,128,.5);}}
    .abadge{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:6px;
             font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-left:8px;}}
    .geo-row{{display:flex;justify-content:space-between;align-items:center;
              padding:8px 0;border-bottom:1px solid var(--border);font-size:.83rem;}}
    .mono{{font-family:monospace;color:#007AFF;}}
    .dim{{opacity:.45;font-size:.75rem;font-style:italic;}}
    [data-testid="stMetricValue"]{{font-size:2rem!important;}}
    [data-testid="stMetricLabel"]{{opacity:.5!important;font-size:.72rem!important;}}
    .js-plotly-plot .plotly .main-svg{{background:transparent!important;}}
    .stDownloadButton>button{{width:100%;background:rgba(0,122,255,.1)!important;
        border:1px solid rgba(0,122,255,.3)!important;color:#007AFF!important;}}
    </style>""", unsafe_allow_html=True)


def _icon(path, w=20, h=20):
    return f'<svg width="{w}" height="{h}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:6px">{path}</svg>'

import base64
try:
    with open("dot-timeline-template-png.png", "rb") as _f:
        _b64 = base64.b64encode(_f.read()).decode()
        SHIELD = f'<img src="data:image/png;base64,{_b64}" style="width:42px;height:42px;object-fit:contain;">'
except Exception:
    SHIELD = _icon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', 22, 22)
ACTIVITY = _icon('<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>')
ALERT_IC = _icon('<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>')
GLOBE    = _icon('<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>')
DNS_IC   = _icon('<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>')


def _init_session():
    ss = st.session_state
    if "session_start"   not in ss: ss.session_start   = datetime.datetime.now()
    if "alert_history"   not in ss: ss.alert_history   = []
    if "theme"           not in ss: ss.theme           = "Dark"
    if "email_cfg"       not in ss: ss.email_cfg       = {}
    if "email_alerts_on" not in ss: ss.email_alerts_on = False
    if "replay_thread"   not in ss: ss.replay_thread   = None


def _navbar(df):
    ss = st.session_state
    on = capture.is_capturing
    cnt = len(capture.captured_packets)

    st.markdown("""<style>
    .nav-container { padding: 10px 0; margin-bottom: 20px; border-bottom: 1px solid var(--border); }
    </style>""", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns([3, 1.5, 1.5, 1.2])

    with c1:
        st.markdown(f"""
            <div style="margin-top:-30px;display:flex;align-items:center;gap:16px">
                <div style="background:#007AFF;padding:10px;border-radius:12px;color:#fff">{SHIELD}</div>
                <div style="flex:1">
                    <h1 style="font-size:2.4rem;margin:0;font-weight:700;letter-spacing:-.03em">Sentinel</h1>
                    <p style="opacity:.45;font-size:.8rem;margin-top:2px">NETWORK TRAFFIC ANALYZER</p>
                </div>
                <div style="text-align:right;margin-right:20px;">
                    <div style="font-size:1.8rem;font-weight:700;color:#007AFF">{cnt:,}</div>
                    <div style="font-size:.65rem;opacity:.4;letter-spacing:.08em">PACKETS CAPTURED</div>
                </div>
            </div>""", unsafe_allow_html=True)

    with c2:
        st.markdown(f"""<p style='font-size:.68rem;font-weight:700;opacity:.4;letter-spacing:.1em;margin-bottom:8px;margin-top:0;'>CONTROL INTERFACE</p>
            <div class="pill {'pill-on' if on else 'pill-off'}">
                <span class="dot {'dot-on' if on else 'dot-off'}"></span>
                {'Live Capture' if on else 'Capture Paused'}
            </div>""", unsafe_allow_html=True)

    with c3:
        elapsed = str(datetime.datetime.now() - ss.session_start).split(".")[0]
        buf_pct = int(cnt / capture.MAX_PACKETS * 100)
        st.markdown(f"""<div style='font-size:.85rem;opacity:.8;line-height:1.6;margin-top:4px'>
            ⏱ Session: <b>{elapsed}</b><br>
            📦 Buffer: <b>{cnt:,} / {capture.MAX_PACKETS:,}</b> ({buf_pct}%)<br>
            🔔 Alerts: <b>{len(ss.alert_history)}</b> this session
        </div>""", unsafe_allow_html=True)

    with c4:
        st.write("") # spacer
        csv_b = get_csv_bytes(capture.captured_packets)
        fname = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        st.download_button("⬇ Download CSV", csv_b or b"", fname, "text/csv", disabled=not csv_b, use_container_width=True)
        if st.button("🗑 Reset Session", use_container_width=True):
            capture.captured_packets.clear(); capture.dns_queries.clear()
            ss.alert_history.clear(); reset_notifications(); st.rerun()

    st.write("---")
    # Return defaults: proto_filter, ps_thresh, fl_thresh, syn_thresh
    return "All", 10, 100, 50


def show_dashboard():
    st.set_page_config(page_title="Sentinel | Network Traffic Analyzer", layout="wide")
    _init_session()
    _css(st.session_state.theme)

    # Auto-start
    if not capture.is_capturing:
        capture.start_capture_thread()
        time.sleep(0.5)

    proto_filter, ps_thresh, fl_thresh, syn_thresh = _navbar(None)

    df, summary, proto_dist = analyze_packets(capture.captured_packets)
    df_view = df[df["protocol"] == proto_filter].copy() if (not df.empty and proto_filter != "All") else df.copy()

    # ── Empty state ───────────────────────────────────────────────────────────
    if df.empty:
        st.markdown('<div class="kard" style="text-align:center;padding:100px 20px"><h3 style="opacity:.5;font-weight:400">Waiting for traffic…</h3><p style="opacity:.35">Sniffing engine initializing. Packets will appear here.</p></div>', unsafe_allow_html=True)
    else:
        # ── Metrics (#4 ARP shown) ────────────────────────────────────────────
        c = st.columns(6)
        c[0].metric("TOTAL",     f"{summary['total']:,}")
        c[1].metric("TCP",       f"{summary['tcp']:,}")
        c[2].metric("UDP",       f"{summary['udp']:,}")
        c[3].metric("ICMP",      f"{summary['icmp']:,}")
        c[4].metric("ARP",       f"{summary['arp']:,}")
        c[5].metric("THROUGHPUT",summary["total_size"])
        st.write("---")

        # ── Row 1: Protocol pie + Top Source IPs + Top Dest IPs ────────────────
        r1a, r1b, r1c = st.columns(3)
        with r1a:
            st.markdown(f"{ACTIVITY} **Protocol Mix**", unsafe_allow_html=True)
            fig = px.pie(values=list(proto_dist.values()), names=list(proto_dist.keys()),
                         hole=.75, color_discrete_sequence=COLORS)
            fig.update_layout(**CHART_LAYOUT, showlegend=True,
                legend=dict(orientation="h",yanchor="bottom",y=-.2,xanchor="center",x=.5))
            st.plotly_chart(fig, use_container_width=True)
        with r1b:
            st.markdown(f"{ACTIVITY} **Top Source IPs**", unsafe_allow_html=True)
            if summary["top_src"]:
                src_df = pd.DataFrame(list(summary["top_src"].items()), columns=["IP","Count"])
                fig2 = px.bar(src_df, x="IP", y="Count", color_discrete_sequence=["#007AFF"])
                fig2.update_layout(**CHART_LAYOUT, xaxis_title=None, yaxis_title=None)
                st.plotly_chart(fig2, use_container_width=True)
        with r1c:
            st.markdown(f"{ACTIVITY} **Top Destination IPs**", unsafe_allow_html=True)
            if summary["top_dst"]:
                dst_df = pd.DataFrame(list(summary["top_dst"].items()), columns=["IP","Count"])
                fig3 = px.bar(dst_df, x="IP", y="Count", color_discrete_sequence=["#5E5CE6"])
                fig3.update_layout(**CHART_LAYOUT, xaxis_title=None, yaxis_title=None)
                st.plotly_chart(fig3, use_container_width=True)
        st.write("---")

        # ── Row 2: Traffic Over Time + IP Intelligence ────────────────────────
        r2a, r2b = st.columns([3, 2])
        with r2a:
            ts = get_time_series(df_view)
            if not ts.empty:
                st.markdown(f"{ACTIVITY} **Traffic Over Time** (packets/sec)", unsafe_allow_html=True)
                fig_ts = px.line(ts, x="timestamp", y="count", color_discrete_sequence=["#007AFF"])
                fig_ts.update_layout(**CHART_LAYOUT, xaxis_title=None, yaxis_title=None)
                fig_ts.update_traces(fill="tozeroy", fillcolor="rgba(0,122,255,.1)")
                st.plotly_chart(fig_ts, use_container_width=True)
        with r2b:
            st.markdown(f"{GLOBE} **IP Intelligence**", unsafe_allow_html=True)
            top_ips = list({**summary["top_src"], **summary["top_dst"]}.keys())[:6]
            rows = ""
            for ip in top_ips:
                loc  = get_ip_info(ip)
                host = get_hostname(ip)
                hlbl = f"({host})" if host != ip else ""
                rows += f'<div class="geo-row"><div><span class="mono">{ip}</span> <span class="dim">{hlbl}</span></div><span style="opacity:.7">📍 {loc}</span></div>'
            st.markdown(f'<div class="kard" style="padding:14px">{rows}</div>', unsafe_allow_html=True)
        st.write("---")

        # ── Row 3: Size hist + TCP flags + Threat Intelligence ────────────────
        r3a, r3b, r3c = st.columns(3)
        with r3a:
            sz = get_size_distribution(df_view)
            if sz:
                st.markdown("**Packet Size Distribution**", unsafe_allow_html=True)
                fig_sz = px.bar(x=list(sz.keys()), y=list(sz.values()),
                                color_discrete_sequence=["#FF9500"])
                fig_sz.update_layout(**CHART_LAYOUT, xaxis_title=None, yaxis_title=None)
                st.plotly_chart(fig_sz, use_container_width=True)
        with r3b:
            flags = get_tcp_flag_counts(df_view)
            if flags:
                st.markdown("**TCP Flag Distribution**", unsafe_allow_html=True)
                fig_fl = px.bar(x=list(flags.keys()), y=list(flags.values()),
                                color_discrete_sequence=["#5E5CE6"])
                fig_fl.update_layout(**CHART_LAYOUT, xaxis_title=None, yaxis_title=None)
                st.plotly_chart(fig_fl, use_container_width=True)
        with r3c:
            alerts = detect_alerts(df, ps_thresh, fl_thresh, syn_thresh)
            known = {f"{a['type']}|{a['message']}" for a in st.session_state.alert_history}
            for a in alerts:
                key = f"{a['type']}|{a['message']}"
                if key not in known:
                    a_copy = dict(a); a_copy["ts"] = datetime.datetime.now().strftime("%H:%M:%S")
                    st.session_state.alert_history.append(a_copy)
                    if st.session_state.email_alerts_on and st.session_state.email_cfg.get("smtp_user"):
                        send_email_alert(a, st.session_state.email_cfg)
            if alerts:
                st.markdown(f'<div style="display:flex;align-items:center;color:#FF3B30">{ALERT_IC}<h3 style="margin:0">Threat Intelligence</h3></div>', unsafe_allow_html=True)
                st.write("")
                for a in alerts:
                    s = SEVERITY_STYLE.get(a.get("severity","Medium"), SEVERITY_STYLE["Medium"])
                    st.markdown(f"""<div class="kard" style="background:{s['bg']};border:1px solid {s['border']};padding:16px;margin-bottom:8px">
                        <div style="display:flex;align-items:center;margin-bottom:6px">
                            <span style="font-weight:700;color:{s['color']};font-size:.72rem;letter-spacing:.1em">{a['type']} ALERT</span>
                            <span class="abadge" style="background:{s['badge']};color:{s['color']}">{a.get('severity','?')}</span>
                        </div>
                        <div style="opacity:.9">{a['message']}</div>
                    </div>""", unsafe_allow_html=True)
            if st.session_state.alert_history:
                with st.expander(f"📋 Alert History ({len(st.session_state.alert_history)} total)"):
                    hist_df = pd.DataFrame(st.session_state.alert_history)[["ts","type","severity","message"]]
                    hist_df.columns = ["Time","Type","Severity","Message"]
                    st.dataframe(hist_df, use_container_width=True)

        if flags or sz or alerts:
            st.write("---")

        # ── Row 4: ICMP Type Breakdown ────────────────────────────────────────
        icmp = get_icmp_breakdown(df_view)
        if icmp:
            st.markdown("**ICMP Type Breakdown**", unsafe_allow_html=True)
            fig_ic = px.pie(values=list(icmp.values()), names=list(icmp.keys()),
                            hole=.5, color_discrete_sequence=COLORS)
            fig_ic.update_layout(**CHART_LAYOUT, showlegend=True,
                legend=dict(orientation="h",yanchor="bottom",y=-.3,xanchor="center",x=.5))
            st.plotly_chart(fig_ic, use_container_width=True)
            st.write("---")

        # ── DNS Query Tracker (#19) ───────────────────────────────────────────
        top_domains = get_top_domains(capture.dns_queries)
        if top_domains:
            st.markdown(f"{DNS_IC} **DNS Query Log**", unsafe_allow_html=True)
            d1, d2 = st.columns([2,3])
            with d1:
                dns_df = pd.DataFrame(list(top_domains.items()), columns=["Domain","Queries"])
                st.dataframe(dns_df, use_container_width=True, hide_index=True)
            with d2:
                fig_dns = px.bar(dns_df.head(8), x="Queries", y="Domain",
                                 orientation="h", color_discrete_sequence=["#34C759"])
                fig_dns.update_layout(**CHART_LAYOUT, xaxis_title=None, yaxis_title=None)
                st.plotly_chart(fig_dns, use_container_width=True)
            st.write("---")

        # ── World Map (#18) ───────────────────────────────────────────────────
        if HAS_FOLIUM:
            map_ips = list({**summary["top_src"], **summary["top_dst"]}.keys())[:10]
            coords  = [(ip, get_ip_coords(ip)) for ip in map_ips]
            coords  = [(ip, c) for ip, c in coords if c]
            if coords:
                st.markdown(f"{GLOBE} **Traffic Origin Map**", unsafe_allow_html=True)
                m = folium.Map(location=[20, 0], zoom_start=2,
                               tiles="CartoDB dark_matter")
                for ip, (lat, lon) in coords:
                    folium.CircleMarker([lat, lon], radius=8, color="#007AFF",
                        fill=True, fill_color="#007AFF", fill_opacity=.6,
                        popup=f"{ip} — {get_ip_info(ip)}").add_to(m)
                st_folium(m, use_container_width=True, height=350)
                st.write("---")
        else:
            st.info("💡 Install `folium` and `streamlit-folium` to enable the world map.", icon="🗺️")

        # ── Packet log (filtered) ─────────────────────────────────────────────
        lbl = f" — {proto_filter} only" if proto_filter != "All" else ""
        st.markdown(f"<p style='font-size:.72rem;font-weight:700;opacity:.4;letter-spacing:.1em'>INGESTION LOG{lbl}</p>", unsafe_allow_html=True)
        st.dataframe(df_view.tail(20), use_container_width=True)



    # ── Auto-refresh ──────────────────────────────────────────────────────────
    if capture.is_capturing:
        time.sleep(1)
        st.rerun()


if __name__ == "__main__":
    show_dashboard()
