"""
monitor.py

Entry point for the Attack Surface Drift Monitor.
Runs the full pipeline: scan -> store -> diff -> score -> report.
"""

from scanner import scan_host, ScanError
from state_store import StateStore
from diff_engine import diff_snapshots
from risk_scorer import score_diff
from report import generate_report


def run_once(host: str, label: str,
             db_path: str = "./data/snapshots.db",
             report_path: str = "./reports/latest.html"):

    print(f"Scanning {host} ({label}) ...")
    try:
        findings = scan_host(host)
    except ScanError as e:
        print(f"Scan failed: {e}")
        return

    print(f"Found {len(findings)} finding(s). Saving snapshot ...")
    store = StateStore(db_path)
    scan_id = store.save_snapshot(host=host, label=label, findings=findings)
    print(f"Saved as scan_id={scan_id}")

    print("Comparing against previous scan ...")
    previous, latest = store.get_last_two_scans(host)
    diff = diff_snapshots(previous, latest)

    print("Scoring risk ...")
    scored = score_diff(diff)

    print("Generating report ...")
    path = generate_report(host, label, scored, output_path=report_path)

    print()
    print("=== SUMMARY ===")
    print(f"New: {scored['summary']['counts']['new']}")
    print(f"Removed: {scored['summary']['counts']['removed']}")
    print(f"Changed: {scored['summary']['counts']['changed']}")
    print(f"Unchanged: {scored['summary']['counts']['unchanged']}")
    print(f"Total risk score: {scored['summary']['total_risk']}")
    print(f"Report: {path}")


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.101"
    run_once(host=target, label="metasploitable2")
