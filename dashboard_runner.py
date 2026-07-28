"""Streamlit entry point for the SOC Dashboard.

This file exists so Streamlit can run the dashboard via:
    streamlit run dashboard_runner.py

It also works when installed as a package:
    streamlit run $(python -c "import ssh_honeypot.dashboard; print(ssh_honeypot.dashboard.__file__)")
"""

from ssh_honeypot.dashboard import render_dashboard

if __name__ == "__main__":
    render_dashboard()
