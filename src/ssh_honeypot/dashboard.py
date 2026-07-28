"""Streamlit SOC Dashboard for SSH Honeypot.

Renders a real-time security operations center monitoring dashboard
with attack statistics, charts, geolocation map, live feed, filtering
capabilities, and data export functionality.
"""

import os
import re

import folium
import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_folium import st_folium

from ssh_honeypot.config import config
from ssh_honeypot.database import (
    export_csv,
    export_excel,
    export_json,
    get_all_logs,
    get_asn_stats,
    get_country_stats,
    get_today_count,
    get_total_count,
    get_unique_countries,
    get_unique_ips,
    get_username_stats,
)

COLORS = {
    "dark": {
        "canvas": "#2b2622",
        "canvas_soft": "#383330",
        "hairline": "#3f3a36",
        "primary": "#f7f5f0",
        "body_strong": "#dad2c1",
        "body": "#c9c0ad",
        "mute": "#aea69c",
        "accent": "#f77f00",
        "accent_red": "#ef476f",
        "accent_green": "#06d6a0",
        "accent_cyan": "#00d4ff",
        "accent_yellow": "#ffd166",
        "accent_purple": "#7b2cbf",
    },
    "light": {
        "canvas": "#f7f5f0",
        "canvas_soft": "#e8e0d8",
        "hairline": "#d4c8b8",
        "primary": "#2b2622",
        "body_strong": "#5a4e3e",
        "body": "#8a7e6e",
        "mute": "#aea69c",
        "accent": "#c05d10",
        "accent_red": "#c0392b",
        "accent_green": "#1a8a5c",
        "accent_cyan": "#0a6e8a",
        "accent_yellow": "#e6a817",
        "accent_purple": "#6a1b9a",
    },
}

SPACING = {
    "xxs": "2px",
    "xs": "4px",
    "sm": "8px",
    "md": "10px",
    "lg": "16px",
    "xl": "24px",
    "2xl": "32px",
    "3xl": "48px",
}

RADIUS = {"xxs": "1px", "xs": "2px", "sm": "3px", "md": "4px", "lg": "6px", "pill": "9999px"}


def _c(theme: str = "dark") -> dict:
    return COLORS.get(theme, COLORS["dark"])


_HTML_ESCAPE_RE = re.compile(r"[&<>\"']")


def _escape_html(value: object) -> str:
    """Escape a value for safe insertion into HTML."""
    text = str(value) if value is not None else ""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace('"', "&quot;").replace("'", "&#39;")
    return text


def _plotly_layout(c: dict) -> dict:
    """Return common Plotly figure layout for dark theme charts."""
    return {
        "paper_bgcolor": c["canvas_soft"],
        "plot_bgcolor": c["canvas_soft"],
        "font": {"color": c["primary"]},
        "margin": {"l": 0, "r": 0, "t": 0, "b": 0},
        "xaxis": {"gridcolor": c["hairline"], "zeroline": False},
        "yaxis": {"gridcolor": c["hairline"], "zeroline": False},
    }


def _apply_design(theme: str = "dark") -> None:
    """Apply custom CSS styling based on the selected theme."""
    c = _c(theme)
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=DM+Mono:wght@400&display=swap');

        *, *::before, *::after {{ box-sizing: border-box; }}

        .stApp {{
            background-color: {c["canvas"]};
            color: {c["primary"]};
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            font-size: 14px;
            line-height: 1.5;
        }}

        .page-header {{
            background-color: {c["canvas"]};
            border-bottom: 1px solid {c["hairline"]};
            padding: {SPACING["xl"]} {SPACING["xl"]} {SPACING["lg"]};
            margin-bottom: {SPACING["xl"]};
        }}
        .page-header h1 {{
            font-size: 28px;
            font-weight: 600;
            letter-spacing: -0.02em;
            margin: 0 0 4px;
            color: {c["primary"]};
        }}
        .page-header p {{
            margin: 0;
            color: {c["body"]};
            font-size: 13px;
        }}

        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: {SPACING["md"]};
            margin-bottom: {SPACING["xl"]};
        }}
        @media (max-width: 900px) {{
            .stat-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}

        .stat-card {{
            background-color: {c["canvas_soft"]};
            border: 1px solid {c["hairline"]};
            border-radius: {RADIUS["md"]};
            padding: {SPACING["lg"]} {SPACING["xl"]};
            transition: border-color 0.2s;
        }}
        .stat-card:hover {{
            border-color: {c["accent"]};
        }}
        .stat-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: {c["mute"]};
            margin-bottom: {SPACING["xs"]};
            font-weight: 500;
        }}
        .stat-value {{
            font-size: 22px;
            font-weight: 600;
            color: {c["primary"]};
            font-family: 'Inter', monospace;
            line-height: 1.2;
        }}
        .stat-sub {{
            font-size: 11px;
            color: {c["body"]};
            margin-top: {SPACING["xxs"]};
        }}

        .section-title {{
            font-size: 18px;
            font-weight: 600;
            color: {c["primary"]};
            margin: 0 0 {SPACING["lg"]};
            padding-bottom: {SPACING["sm"]};
            border-bottom: 2px solid {c["accent"]};
            letter-spacing: -0.01em;
        }}

        .chart-panel {{
            background-color: {c["canvas_soft"]};
            border: 1px solid {c["hairline"]};
            border-radius: {RADIUS["md"]};
            padding: {SPACING["lg"]};
            margin-bottom: {SPACING["md"]};
        }}

        .feed-row {{
            background-color: {c["canvas_soft"]};
            border: 1px solid {c["hairline"]};
            border-radius: {RADIUS["md"]};
            padding: {SPACING["sm"]} {SPACING["lg"]};
            margin-bottom: {SPACING["xs"]};
            display: flex;
            align-items: center;
            gap: {SPACING["md"]};
            font-family: 'DM Mono', monospace;
            font-size: 12px;
        }}
        .feed-time {{ color: {c["mute"]}; min-width: 140px; }}
        .feed-ip {{ color: {c["accent_cyan"]}; font-weight: 500; min-width: 120px; }}
        .feed-country {{ color: {c["body_strong"]}; min-width: 80px; }}
        .feed-user {{ color: {c["body"]}; flex: 1; }}
        .feed-badge {{
            padding: 2px 8px;
            border-radius: {RADIUS["xs"]};
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.03em;
        }}
        .badge-fail {{ background-color: rgba(239,71,111,0.15); color: {c["accent_red"]}; }}
        .badge-ok {{ background-color: rgba(6,214,160,0.15); color: {c["accent_green"]}; }}

        .data-table {{
            background-color: {c["canvas_soft"]};
            border: 1px solid {c["hairline"]};
            border-radius: {RADIUS["md"]};
            overflow: hidden;
        }}

        div[data-testid="stSidebar"] {{
            background-color: {c["canvas"]};
            border-right: 1px solid {c["hairline"]};
        }}
        .sidebar-section {{
            padding: {SPACING["sm"]} {SPACING["lg"]};
        }}
        .sidebar-title {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: {c["mute"]};
            margin-bottom: {SPACING["sm"]};
            font-weight: 500;
        }}

        .stTabs > div > div > div[data-baseweb="tab"] {{
            color: {c["body"]};
            font-size: 13px;
            font-weight: 500;
        }}
        .stTabs > div > div > div[data-baseweb="tab-selected"] {{
            color: {c["primary"]};
            border-bottom: 2px solid {c["accent"]};
        }}

        .stButton > button {{
            background-color: {c["accent"]};
            color: {c["canvas"]};
            border: none;
            border-radius: {RADIUS["sm"]};
            font-weight: 600;
            font-size: 13px;
            padding: {SPACING["sm"]} {SPACING["lg"]};
            font-family: 'Inter', sans-serif;
        }}

        .stSelectbox label, .stMultiselect label {{
            color: {c["body"]};
            font-size: 12px;
            font-weight: 500;
        }}

        .expander-header {{
            background-color: {c["canvas_soft"]} !important;
            border: 1px solid {c["hairline"]} !important;
            border-radius: {RADIUS["md"]} !important;
        }}

        hr {{ border: none; border-top: 1px solid {c["hairline"]}; margin: {SPACING["lg"]} 0; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_header(theme: str) -> None:
    """Render the dashboard page header."""
    st.markdown(
        """
        <div class="page-header">
            <h1>🛡️ SSH Honeypot SOC</h1>
            <p>Real-time threat intelligence &amp; attack monitoring</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_stats(stats: dict, theme: str) -> None:
    """Render the statistics grid with key metrics."""
    st.markdown('<div class="stat-grid">', unsafe_allow_html=True)

    items = [
        ("Total Attacks", f"{stats.get('total', 0):,}", ""),
        ("Today", str(stats.get("today", 0)), ""),
        ("Unique IPs", f"{stats.get('unique_ips', 0):,}", ""),
        ("Countries", str(stats.get("unique_countries", 0)), ""),
        ("Top User", stats.get("top_username", "N/A"), ""),
        ("Top Country", stats.get("top_country", "N/A"), ""),
        ("Avg Attempts", str(stats.get("avg_attempts", 0)), ""),
        ("Peak Hour", stats.get("peak_hour", "N/A"), ""),
    ]

    for label, value, sub in items:
        st.markdown(
            f"""
            <div class="stat-card">
                <div class="stat-label">{_escape_html(label)}</div>
                <div class="stat-value">{_escape_html(value)}</div>
                {"<div class='stat-sub'>" + _escape_html(sub) + "</div>" if sub else ""}
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)


def _render_overview(df: pd.DataFrame, theme: str) -> None:
    """Render the overview page with summary stats and timeline."""
    st.markdown('<div class="section-title">Overview</div>', unsafe_allow_html=True)

    if df.empty:
        st.info("No attack data available yet. Waiting for connections...")
        return

    total = len(df)
    today = get_today_count()
    unique_ips = get_unique_ips()
    unique_countries = get_unique_countries()

    username_counts = df["username"].value_counts()
    top_username = username_counts.index[0] if len(username_counts) > 0 else "N/A"

    country_counts = df["country"].value_counts()
    top_country = country_counts.index[0] if len(country_counts) > 0 else "N/A"

    avg_attempts = df["attempts"].mean() if "attempts" in df.columns else 0

    if "timestamp" in df.columns:
        df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
        peak_hour = int(df["hour"].mode()[0]) if len(df["hour"].mode()) > 0 else 0
        peak_hour_str = f"{peak_hour:02d}:00"
    else:
        peak_hour_str = "N/A"

    stats = {
        "total": total,
        "today": today,
        "unique_ips": unique_ips,
        "unique_countries": unique_countries,
        "top_username": top_username,
        "top_country": top_country,
        "avg_attempts": round(avg_attempts, 1),
        "peak_hour": peak_hour_str,
    }

    _render_stats(stats, theme)

    if "timestamp" in df.columns:
        df["date"] = pd.to_datetime(df["timestamp"]).dt.date
        timeline = df.groupby("date").size().reset_index(name="attacks")
        timeline.columns = ["Date", "Attacks"]

        c = _c(theme)
        fig = px.area(
            timeline,
            x="Date",
            y="Attacks",
            title="",
            color_discrete_sequence=[c["accent"]],
            template="plotly_dark",
        )
        fig.update_layout(**_plotly_layout(c))
        st.plotly_chart(fig, width="stretch", theme="streamlit")


def _render_charts(df: pd.DataFrame, theme: str) -> None:
    """Render the charts page with multiple attack visualizations."""
    st.markdown('<div class="section-title">Charts</div>', unsafe_allow_html=True)

    if df.empty:
        st.info("No chart data available yet.")
        return

    c = _c(theme)
    chart1, chart2 = st.columns(2)

    with chart1:
        st.markdown('<div class="chart-panel">', unsafe_allow_html=True)
        if "timestamp" in df.columns:
            df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
            hourly = df.groupby("hour").size().reset_index(name="attacks")
            hourly.columns = ["Hour", "Attacks"]
            fig = px.bar(
                hourly,
                x="Hour",
                y="Attacks",
                title="Hourly Attacks",
                color_discrete_sequence=[c["accent_cyan"]],
                template="plotly_dark",
            )
            fig.update_layout(**_plotly_layout(c))
            st.plotly_chart(fig, width="stretch", theme="streamlit")

        username_counts = df["username"].value_counts().head(10)
        fig = px.bar(
            username_counts.reset_index(),
            x="username",
            y="count",
            title="Top Targeted Usernames",
            color_discrete_sequence=[c["accent_red"]],
            template="plotly_dark",
        )
        fig.update_layout(**_plotly_layout(c))
        st.plotly_chart(fig, width="stretch", theme="streamlit")
        st.markdown("</div>", unsafe_allow_html=True)

    with chart2:
        st.markdown('<div class="chart-panel">', unsafe_allow_html=True)
        if "timestamp" in df.columns:
            df["date"] = pd.to_datetime(df["timestamp"]).dt.date
            daily = df.groupby("date").size().reset_index(name="attacks")
            daily.columns = ["Date", "Attacks"]
            fig = px.scatter(
                daily,
                x="Date",
                y="Attacks",
                title="Daily Attacks",
                color_discrete_sequence=[c["accent_yellow"]],
                template="plotly_dark",
            )
            fig.update_layout(**_plotly_layout(c))
            st.plotly_chart(fig, width="stretch", theme="streamlit")

        country_counts = df["country"].value_counts().head(10)
        fig = px.pie(
            country_counts.reset_index(),
            names="country",
            values="count",
            title="Top Source Countries",
            color_discrete_sequence=px.colors.qualitative.Set3,
            template="plotly_dark",
        )
        fig.update_layout(**_plotly_layout(c))
        st.plotly_chart(fig, width="stretch", theme="streamlit")

        auth_counts = df["auth_method"].value_counts()
        fig = px.pie(
            auth_counts.reset_index(),
            names="auth_method",
            values="count",
            title="Attack Vector Breakdown",
            color_discrete_sequence=[c["accent_red"], c["accent_yellow"], c["accent_purple"], c["accent_cyan"]],
            template="plotly_dark",
        )
        fig.update_layout(**_plotly_layout(c))
        st.plotly_chart(fig, width="stretch", theme="streamlit")
        st.markdown("</div>", unsafe_allow_html=True)

    chart3, chart4 = st.columns(2)

    with chart3:
        st.markdown('<div class="chart-panel">', unsafe_allow_html=True)
        ip_counts = df["ip"].value_counts().head(10)
        fig = px.bar(
            ip_counts.reset_index(),
            x="ip",
            y="count",
            title="Top Source IPs",
            color_discrete_sequence=[c["accent_red"]],
            template="plotly_dark",
        )
        fig.update_layout(**_plotly_layout(c))
        st.plotly_chart(fig, width="stretch", theme="streamlit")

        asn_stats = get_asn_stats()
        if asn_stats:
            asn_df = pd.DataFrame(asn_stats)
            fig = px.bar(
                asn_df.head(10),
                x="asn",
                y="count",
                title="Most Active ASN",
                color_discrete_sequence=[c["accent"]],
                template="plotly_dark",
            )
            fig.update_layout(**_plotly_layout(c))
            st.plotly_chart(fig, width="stretch", theme="streamlit")
        st.markdown("</div>", unsafe_allow_html=True)

    with chart4:
        st.markdown('<div class="chart-panel">', unsafe_allow_html=True)
        if "timestamp" in df.columns and "country" in df.columns:
            heatmap_data = df.copy()
            heatmap_data["hour"] = pd.to_datetime(heatmap_data["timestamp"]).dt.hour
            heatmap_data["day_of_week"] = pd.to_datetime(heatmap_data["timestamp"]).dt.day_name()
            pivot = heatmap_data.pivot_table(
                index="day_of_week",
                columns="hour",
                values="ip",
                aggfunc="count",
                fill_value=0,
            )
            fig = px.imshow(
                pivot,
                title="Attack Heatmap (Day x Hour)",
                color_continuous_scale="YlOrRd",
                template="plotly_dark",
            )
            fig.update_layout(**_plotly_layout(c))
            st.plotly_chart(fig, width="stretch", theme="streamlit")

        if "timestamp" in df.columns:
            df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
            hourly_data = df.groupby("hour").size().reset_index(name="count")
            hourly_data.columns = ["Hour", "Count"]
            fig = px.line(
                hourly_data,
                x="Hour",
                y="Count",
                title="Attack Trend (Hourly)",
                color_discrete_sequence=[c["accent_green"]],
                template="plotly_dark",
            )
            fig.update_layout(**_plotly_layout(c))
            st.plotly_chart(fig, width="stretch", theme="streamlit")
        st.markdown("</div>", unsafe_allow_html=True)


def _render_map(df: pd.DataFrame) -> None:
    """Render the interactive Folium geolocation map with GeoIP setup guidance."""
    st.markdown('<div class="section-title">Interactive Map</div>', unsafe_allow_html=True)

    if df.empty:
        st.info("No attack data available yet. Waiting for connections...")
        return

    valid = df[(df["latitude"] != 0.0) & (df["longitude"] != 0.0) & df["latitude"].notna() & df["longitude"].notna()]

    if valid.empty:
        c = _c(st.session_state.get("theme", "dark"))
        st.markdown(
            f"""
            <div style="
                background:{c["canvas_soft"]};
                border:1px solid {c["accent_yellow"]};
                border-radius:4px; padding:16px; margin-bottom:16px;
            ">
                <div style="color:{c["accent_yellow"]}; font-weight:600; margin-bottom:8px;">
                    ⚡ GeoIP Not Configured
                </div>
                <div style="color:{c["body"]}; font-size:13px; line-height:1.6;">
                    The geolocation map requires MaxMind GeoLite2 databases.
                    Download them from
                    <a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                       style="color:{c["accent_cyan"]};">MaxMind</a>
                    and set in <code>.env</code>:<br>
                    <code>GEOIP_CITY_DB=path/to/GeoLite2-City.mmdb</code><br>
                    <code>GEOIP_ASN_DB=path/to/GeoLite2-ASN.mmdb</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Show a preview table of IPs with their coordinates even without GeoIP
        st.markdown(
            f'<div style="color:{c["body"]}; font-size:13px; margin-bottom:8px;">Attack source IPs (add GeoIP to enable mapping):</div>',
            unsafe_allow_html=True,
        )
        ip_preview = (
            df.groupby("ip")
            .agg(
                Attacks=("username", "count"),
                Last_Seen=("timestamp", "max"),
                Usernames=("username", lambda x: ", ".join(sorted(x.unique())[:5])),
            )
            .reset_index()
            .sort_values("Attacks", ascending=False)
            .head(10)
        )
        st.dataframe(
            ip_preview.rename(
                columns={"ip": "IP Address", "Attacks": "Attempts", "Last_Seen": "Last Seen", "Usernames": "Usernames"}
            ),
            width="stretch",
            height=350,
            hide_index=True,
        )
        return

    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")

    for _, row in valid.iterrows():
        popup_html = (
            f'<div style="font-family:Inter,sans-serif;font-size:12px;color:#f7f5f0;">'
            f"<b>IP:</b> {_escape_html(row.get('ip', 'N/A'))}<br>"
            f"<b>Country:</b> {_escape_html(row.get('country', 'N/A'))}<br>"
            f"<b>City:</b> {_escape_html(row.get('city', 'N/A'))}<br>"
            f"<b>Username:</b> {_escape_html(row.get('username', 'N/A'))}<br>"
            f"<b>Timestamp:</b> {_escape_html(row.get('timestamp', 'N/A'))}<br>"
            f"<b>Attempts:</b> {_escape_html(row.get('attempts', 1))}<br>"
            f"<b>Status:</b> {_escape_html(row.get('status', 'N/A'))}<br>"
            f"<b>ASN:</b> {_escape_html(row.get('asn', 'N/A'))}"
            f"</div>"
        )
        radius = min(max(row.get("attempts", 1) * 2, 4), 20)
        folium.CircleMarker(
            location=[row["latitude"], row["longitude"]],
            radius=radius,
            popup=folium.Popup(popup_html, max_width=300),
            color="#ef476f",
            fill=True,
            fill_color="#ef476f",
            fill_opacity=0.7,
            weight=1,
        ).add_to(m)

    st_folium(m, width=None, height=600)


def _render_live_feed(df: pd.DataFrame, theme: str) -> None:
    """Render the live attack feed with rich details and auto-refresh."""
    c = _c(theme)
    st.markdown('<div class="section-title">Live Feed</div>', unsafe_allow_html=True)

    if df.empty:
        st.info("No attack data yet. Waiting for connections...")
        return

    # Auto-refresh control - checks every 5s when enabled
    import time as _time

    auto_refresh = st.checkbox("Auto-refresh (5s)", value=True, key="feed_autorefresh")
    if auto_refresh:
        placeholder = st.empty()
        with placeholder:
            _time.sleep(5)
        st.rerun()

    col_count = len(df)
    last_min = (
        df[df["timestamp"] >= (pd.Timestamp.now() - pd.Timedelta(minutes=1)).isoformat()]
        if "timestamp" in df.columns
        else pd.DataFrame()
    )
    st.markdown(
        f'<div style="color:{c["body"]}; font-size:12px; margin-bottom:12px;">'
        f"{col_count} total events | {len(last_min)} in last 60s "
        f"| showing latest 50"
        f"</div>",
        unsafe_allow_html=True,
    )

    feed_df = df[["timestamp", "ip", "country", "username", "auth_method", "attempts", "asn", "status"]].head(50)

    for _, row in feed_df.iterrows():
        timestamp = str(row.get("timestamp", ""))[:19] if row.get("timestamp") else ""
        ip = _escape_html(row.get("ip", ""))
        country = _escape_html(row.get("country", "??"))
        username = _escape_html(row.get("username", ""))
        auth_method = _escape_html(row.get("auth_method", "?"))
        attempts = int(row.get("attempts", 1))
        asn = _escape_html(str(row.get("asn", ""))[:12])
        status = str(row.get("status", "failure"))

        # Color-code auth methods
        auth_colors = {
            "password": c["accent_red"],
            "publickey": c["accent_yellow"],
            "keyboard-interactive": c["accent_purple"],
            "none": c["accent_cyan"],
        }
        auth_color = auth_colors.get(row.get("auth_method", ""), c["mute"])

        badge_class = "badge-fail" if status == "failure" else "badge-ok"
        status_label = "FAIL" if status == "failure" else "OK"

        st.markdown(
            f"""
            <div class="feed-row">
                <span class="feed-time">{_escape_html(timestamp)}</span>
                <span class="feed-ip">{ip}</span>
                <span class="feed-country">{country}</span>
                <span class="feed-user">{username}</span>
                <span style="color:{auth_color}; font-size:11px; min-width:60px;">{auth_method}</span>
                <span style="color:{c["mute"]}; font-size:11px; min-width:20px;">x{attempts}</span>
                <span style="color:{c["body"]}; font-size:10px; min-width:80px;">{asn}</span>
                <span class="feed-badge {badge_class}">{status_label}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_filters(df: pd.DataFrame) -> pd.DataFrame:
    """Render filter controls and return filtered dataframe."""
    c = _c(st.session_state.get("theme", "dark"))
    st.markdown('<div class="section-title">Filters & Search</div>', unsafe_allow_html=True)

    total = len(df)
    st.markdown(
        f'<div style="color:{c["body"]}; font-size:13px; margin-bottom:12px;">'
        f"<b>{total}</b> record{'s' if total != 1 else ''} in database"
        f"</div>",
        unsafe_allow_html=True,
    )

    with st.expander("Filter Attacks", expanded=True):
        cols = st.columns(4)
        with cols[0]:
            all_countries = (
                sorted([x for x in df["country"].unique().tolist() if x != "Unknown"])
                if "country" in df.columns and not df.empty
                else []
            )
            unknown_country = len(df[df["country"] == "Unknown"]) if "country" in df.columns else 0
            country_options = all_countries
            if unknown_country > 0:
                country_options = ["Unknown (no GeoIP)", *all_countries]
            st.multiselect(
                "Country",
                country_options,
                key="country_filter",
                help=f"Unknown: {unknown_country} records (install GeoIP to resolve)"
                if unknown_country > 0
                else "Filter by country",
            )
        with cols[1]:
            all_usernames = (
                sorted(df["username"].unique().tolist()) if "username" in df.columns and not df.empty else []
            )
            st.multiselect("Username", all_usernames, key="username_filter")
        with cols[2]:
            all_statuses = sorted(df["status"].unique().tolist()) if "status" in df.columns and not df.empty else []
            st.multiselect("Status", all_statuses, key="status_filter")
        with cols[3]:
            all_ips = sorted(df["ip"].unique().tolist()) if "ip" in df.columns and not df.empty else []
            st.multiselect("IP Address", all_ips, key="ip_filter")

        if "timestamp" in df.columns:
            d1, d2 = st.columns(2)
            with d1:
                st.date_input("Start Date", value=None, key="start_date")
            with d2:
                st.date_input("End Date", value=None, key="end_date")

    result = df.copy()

    country_filter = st.session_state.get("country_filter", [])
    username_filter = st.session_state.get("username_filter", [])
    status_filter = st.session_state.get("status_filter", [])
    ip_filter = st.session_state.get("ip_filter", [])

    if country_filter:
        # Map "Unknown (no GeoIP)" label back to "Unknown" in data
        mapped = ["Unknown" if v == "Unknown (no GeoIP)" else v for v in country_filter]
        result = result[result["country"].isin(mapped)]
    if username_filter:
        result = result[result["username"].isin(username_filter)]
    if status_filter:
        result = result[result["status"].isin(status_filter)]
    if ip_filter:
        result = result[result["ip"].isin(ip_filter)]

    with st.expander("Search", expanded=False):
        search_query = st.text_input("Search by Username, Country, IP, or ASN", "", key="search_query")
        if search_query:
            query_lower = search_query.lower()
            str_cols = result.select_dtypes(include=["object"]).columns
            mask = (
                result[str_cols]
                .apply(lambda col: col.astype(str).str.lower().str.contains(query_lower, na=False))
                .any(axis=1)
            )
            result = result[mask]

    return result


def _render_stats_tab(df: pd.DataFrame) -> None:
    """Render in-depth statistics tab with rich visualizations."""
    c = _c(st.session_state.get("theme", "dark"))
    st.markdown('<div class="section-title">Statistics</div>', unsafe_allow_html=True)

    if df.empty:
        st.info("No statistics available yet.")
        return

    unique_ips = get_unique_ips()
    unique_countries = get_unique_countries()
    total = len(df)

    # ---- Row 1: Key KPIs ----
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(
            f'<div class="stat-card"><div class="stat-label">Total Attacks</div><div class="stat-value">{total:,}</div></div>',
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            f'<div class="stat-card"><div class="stat-label">Unique IPs</div><div class="stat-value">{unique_ips:,}</div></div>',
            unsafe_allow_html=True,
        )
    with k3:
        avg = round(total / unique_ips, 1) if unique_ips > 0 else 0
        st.markdown(
            f'<div class="stat-card"><div class="stat-label">Avg per IP</div><div class="stat-value">{avg}</div></div>',
            unsafe_allow_html=True,
        )
    with k4:
        st.markdown(
            f'<div class="stat-card"><div class="stat-label">Countries</div><div class="stat-value">{unique_countries}</div></div>',
            unsafe_allow_html=True,
        )
    with k5:
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"])
            peak_hour = int(ts.dt.hour.mode().iloc[0]) if len(ts) > 0 else 0
            st.markdown(
                f'<div class="stat-card"><div class="stat-label">Peak Hour (UTC)</div><div class="stat-value">{peak_hour:02d}:00</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("<hr style='opacity:0.15; margin:12px 0;'>", unsafe_allow_html=True)

    # ---- Row 2: Charts (3 columns) ----
    col_a, col_b = st.columns([3, 2])

    with col_a:
        # Hourly timeline
        if "timestamp" in df.columns:
            st.markdown(
                '<div class="stat-card"><div class="stat-label">Hourly Attack Timeline</div></div>',
                unsafe_allow_html=True,
            )
            ts = pd.to_datetime(df["timestamp"])
            ts_group = ts.dt.floor("h").value_counts().sort_index()
            hourly_df = pd.DataFrame(
                {
                    "hour": ts_group.index,
                    "attacks": ts_group.values,
                }
            )
            fig = px.bar(
                hourly_df,
                x="hour",
                y="attacks",
                labels={"hour": "", "attacks": "Attacks"},
                color_discrete_sequence=["#f77f00"],
                height=220,
            )
            fig.update_layout(
                margin={"l": 10, "r": 10, "t": 10, "b": 30},
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                xaxis={"showgrid": False, "color": c["body"], "tickformat": "%H:%M"},
                yaxis={"showgrid": True, "gridcolor": c["hairline"], "color": c["body"]},
                hovermode="x",
            )
            st.plotly_chart(fig, width="stretch", use_container_width=True)

        # Auth method breakdown
        if "auth_method" in df.columns:
            st.markdown(
                '<div class="stat-card"><div class="stat-label">Auth Method Breakdown</div></div>',
                unsafe_allow_html=True,
            )
            auth_counts = df["auth_method"].value_counts().reset_index()
            auth_counts.columns = ["method", "count"]
            fig2 = px.pie(
                auth_counts,
                values="count",
                names="method",
                color_discrete_sequence=["#ef476f", "#f77f00", "#118ab2", "#06d6a0", "#c9c0ad"],
                height=260,
            )
            fig2.update_layout(
                margin={"l": 10, "r": 10, "t": 10, "b": 10},
                paper_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
            )
            fig2.update_traces(textinfo="label+percent", textfont_color=c["body_strong"])
            st.plotly_chart(fig2, width="stretch", use_container_width=True)

    with col_b:
        # Top attackers table
        st.markdown(
            '<div class="stat-card"><div class="stat-label">Top 10 Attacking IPs</div></div>', unsafe_allow_html=True
        )
        top_ips = df["ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["IP", "Attacks"]
        top_ips["Rank"] = range(1, len(top_ips) + 1)
        st.dataframe(
            top_ips[["Rank", "IP", "Attacks"]],
            width="stretch",
            height=300,
            hide_index=True,
        )

        # Most targeted usernames
        st.markdown(
            '<div class="stat-card"><div class="stat-label">Most Targeted Usernames</div></div>', unsafe_allow_html=True
        )
        top_users = df["username"].value_counts().head(10).reset_index()
        top_users.columns = ["Username", "Attacks"]
        top_users["Rank"] = range(1, len(top_users) + 1)
        st.dataframe(
            top_users[["Rank", "Username", "Attacks"]],
            width="stretch",
            height=300,
            hide_index=True,
        )

    st.markdown("<hr style='opacity:0.15; margin:12px 0;'>", unsafe_allow_html=True)

    # ---- Row 3: More detailed breakdowns ----
    col_x, col_y, col_z = st.columns(3)
    with col_x:
        st.markdown(
            f'<div class="stat-card"><div class="stat-label">Unique Usernames</div><div class="stat-value">{df["username"].nunique()}</div></div>',
            unsafe_allow_html=True,
        )
    with col_y:
        total_unique = df["username"].nunique()
        pct = round(total_unique / total * 100, 1) if total > 0 else 0
        st.markdown(
            f'<div class="stat-card"><div class="stat-label">Username Diversity</div><div class="stat-value">{pct}%</div></div>',
            unsafe_allow_html=True,
        )
    with col_z:
        if "auth_method" in df.columns:
            top_method = df["auth_method"].value_counts().index[0] if len(df) > 0 else "?"
            pct_method = round(df["auth_method"].value_counts().iloc[0] / total * 100, 1) if total > 0 else 0
            st.markdown(
                f'<div class="stat-card"><div class="stat-label">Top Auth Method</div><div class="stat-value">{pct_method}%</div><div class="stat-sub">{top_method}</div></div>',
                unsafe_allow_html=True,
            )

    if unique_ips > 0:
        top_ip = df["ip"].value_counts().index[0]
        top_ip_pct = round(df["ip"].value_counts().iloc[0] / total * 100, 1)
        st.markdown(
            f'<div class="stat-card"><div class="stat-label">Top Attacker</div><div class="stat-value">{top_ip}</div><div class="stat-sub">{top_ip_pct}% of all attacks</div></div>',
            unsafe_allow_html=True,
        )


def _export_pdf() -> str:
    """Generate a PDF report of honeypot statistics.

    Returns:
        Path to the generated PDF file.
    """
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.cell(200, 10, txt="SSH Honeypot Attack Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(5)
    pdf.set_font("Helvetica", size=10)

    total = get_total_count()
    today = get_today_count()
    unique_ips = get_unique_ips()
    unique_countries = get_unique_countries()

    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(200, 8, txt="Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=10)
    for label, val in [
        ("Total Attacks", total),
        ("Today's Attacks", today),
        ("Unique IPs", unique_ips),
        ("Unique Countries", unique_countries),
    ]:
        pdf.cell(200, 6, txt=f"{label}: {val}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(200, 8, txt="Top Targeted Usernames", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=10)
    for entry in get_username_stats()[:10]:
        pdf.cell(200, 6, txt=f"{entry['username']}: {entry['count']} attempts", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(200, 8, txt="Top Source Countries", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=10)
    for entry in get_country_stats()[:10]:
        pdf.cell(200, 6, txt=f"{entry['country']}: {entry['count']} attacks", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    path = os.path.join(os.path.dirname(config.database.db_path), "honeypot_report.pdf")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    pdf.output(path)
    return path


def _render_export() -> None:
    """Render export controls for data export."""
    st.markdown('<div class="section-title">Export Data</div>', unsafe_allow_html=True)

    export_format = st.radio("Export Format", ["CSV", "JSON", "Excel", "PDF Report"], key="export_format")

    if st.button("Generate Export", key="export_button"):
        try:
            paths = {
                "CSV": export_csv,
                "JSON": export_json,
                "Excel": export_excel,
                "PDF Report": _export_pdf,
            }
            path = paths[export_format]()
            st.success(f"Exported to `{path}`")
        except Exception as exc:
            st.error(f"Export failed: {exc}")


def render_dashboard() -> None:
    """Main dashboard render function. Call this from Streamlit."""
    theme = st.session_state.get("theme", config.dashboard.theme)
    _apply_design(theme)

    st.set_page_config(
        page_title=config.dashboard.page_title,
        page_icon=config.dashboard.page_icon,
        layout=config.dashboard.layout,
        initial_sidebar_state=config.dashboard.initial_sidebar_state,
    )

    _render_header(theme)

    with st.sidebar:
        st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-title">Navigation</div>', unsafe_allow_html=True)
        page = st.radio(
            "Navigate",
            ["Overview", "Charts", "Interactive Map", "Live Feed", "Filters & Search", "Statistics", "Export"],
            label_visibility="collapsed",
            key="nav_radio",
        )
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown('<div class="sidebar-title">Theme</div>', unsafe_allow_html=True)
        new_theme = st.selectbox(
            "Appearance",
            ["dark", "light"],
            index=0 if theme == "dark" else 1,
            label_visibility="collapsed",
            key="theme_select",
        )
        st.session_state["theme"] = new_theme
        st.markdown("<hr>", unsafe_allow_html=True)
        st.markdown('<div class="sidebar-title">Quick Stats</div>', unsafe_allow_html=True)
        st.metric("Total Attacks", get_total_count())
        st.metric("Today", get_today_count())
        st.metric("Unique IPs", get_unique_ips())
        st.metric("Countries", get_unique_countries())
        st.markdown("</div>", unsafe_allow_html=True)

    df = pd.DataFrame(get_all_logs())

    if page == "Overview":
        _render_overview(df, theme)
    elif page == "Charts":
        _render_charts(df, theme)
    elif page == "Interactive Map":
        _render_map(df)
    elif page == "Live Feed":
        _render_live_feed(df, theme)
    elif page == "Filters & Search":
        filtered = _render_filters(df)
        st.markdown(f"### Filtered Results ({len(filtered)} records)")
        if not filtered.empty:
            st.dataframe(
                filtered.replace({pd.NA: "", None: ""}),
                width="stretch",
                height=400,
            )
    elif page == "Statistics":
        _render_stats_tab(df)
    elif page == "Export":
        _render_export()


if __name__ == "__main__":
    render_dashboard()
