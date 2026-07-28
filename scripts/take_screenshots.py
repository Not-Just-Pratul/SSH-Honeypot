"""Take screenshots of the SOC Dashboard for GitHub README.

Usage:
    python scripts/take_screenshots.py
"""

import os
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE_URL = "http://localhost:8501"
OUTPUT_DIR = Path("assets/screenshots")


def take_screenshots():
    """Navigate the dashboard and capture screenshots."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=2,
        )
        page = context.new_page()

        # --- 1. Dashboard Overview ---
        print("Taking screenshot: Dashboard Overview...")
        page.goto(BASE_URL, wait_until="networkidle")
        page.wait_for_timeout(3000)  # let charts render
        page.screenshot(path=str(OUTPUT_DIR / "dashboard-overview.png"), full_page=False)
        print("  Saved dashboard-overview.png")

        # --- 2. Interactive Map ---
        print("Taking screenshot: Interactive Map...")
        # Look for a tab/radio button labeled "Map" or "Interactive Map" and click it
        map_selectors = [
            'text=Interactive Map',
            'text=Map',
            '[data-testid="stSidebar"] text=Map',
            'text="Attack Map"',
            'button:has-text("Map")',
            'span:has-text("Map")',
            'p:has-text("Interactive Map")',
        ]
        clicked_map = False
        for sel in map_selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.click()
                    clicked_map = True
                    print(f"  Clicked map tab via: {sel}")
                    break
            except Exception:
                continue

        page.wait_for_timeout(3000)
        page.screenshot(path=str(OUTPUT_DIR / "dashboard-map.png"), full_page=False)
        print("  Saved dashboard-map.png")
        if not clicked_map:
            print("  (Could not find map tab - screenshot shows current view)")

        # --- 3. Live Feed ---
        print("Taking screenshot: Live Feed...")
        feed_selectors = [
            'text=Live Feed',
            'text=Live Attack Feed',
            'text=Few',
            '[data-testid="stSidebar"] text=Feed',
            'button:has-text("Feed")',
            'span:has-text("Live")',
        ]
        for sel in feed_selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.click()
                    print(f"  Clicked feed tab via: {sel}")
                    break
            except Exception:
                continue

        page.wait_for_timeout(3000)
        page.screenshot(path=str(OUTPUT_DIR / "dashboard-feed.png"), full_page=False)
        print("  Saved dashboard-feed.png")

        # --- 4. Statistics ---
        print("Taking screenshot: Statistics...")
        stats_selectors = [
            'text=Statistics',
            'text=Stats',
            'button:has-text("Statistics")',
            'span:has-text("Statistics")',
        ]
        for sel in stats_selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.click()
                    print(f"  Clicked stats tab via: {sel}")
                    break
            except Exception:
                continue

        page.wait_for_timeout(3000)
        page.screenshot(path=str(OUTPUT_DIR / "dashboard-stats.png"), full_page=False)
        print("  Saved dashboard-stats.png")

        # --- 5. API Health (curl-style, but via browser) ---
        print("Taking screenshot: API Health...")
        page.goto("http://localhost:8502/api/health", wait_until="networkidle")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUTPUT_DIR / "api-health.png"), full_page=False)
        print("  Saved api-health.png")

        # --- 6. API Attacks endpoint ---
        print("Taking screenshot: API Attacks...")
        page.goto("http://localhost:8502/api/attacks?limit=5", wait_until="networkidle")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUTPUT_DIR / "api-attacks.png"), full_page=False)
        print("  Saved api-attacks.png")

        browser.close()

    # Report
    files = list(OUTPUT_DIR.glob("*.png"))
    print(f"\nTotal screenshots: {len(files)}")
    for f in sorted(files):
        size = os.path.getsize(f) / 1024
        print(f"  {f.name} ({size:.0f} KB)")


if __name__ == "__main__":
    take_screenshots()
