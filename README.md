# Attack Surface Drift Monitor

A lightweight security tool that continuously scans a host, tracks how its
exposed services change over time, and flags that change by risk — rather
than just producing a one-off scan report.

Built and tested against a Metasploitable2 lab VM.

## Why this exists

Most scan-and-report tools only show you a snapshot: "here's what's open
right now." They don't tell you what's different from last time. In real
environments, the dangerous moment isn't a service that's always been open —
it's a new one that showed up since the last check (a misconfigured
deployment, an unauthorized service, a potential backdoor).

This tool re-scans a target, diffs the result against the previous scan, and
scores each change by how concerning it is — a new exposed port is weighted
far higher than one that quietly closed.

## Architecture

attack-surface-monitor/
    scanner.py        - Nmap wrapper, finds open ports/services
    state_store.py     - SQLite persistence of scan snapshots
    diff_engine.py      - Compares two snapshots, classifies drift
    risk_scorer.py      - Weighs each change by severity
    report.py           - Renders an HTML report
    monitor.py           - Orchestrates the full pipeline
    data/snapshots.db     - SQLite database (created on first run)
    reports/latest.html    - Most recent generated report

Pipeline: scan -> store -> diff -> score -> report, all run from one
command via monitor.py.

Module responsibilities:
- scanner.py: Wraps Nmap (python-nmap) to detect open ports, services, and versions
- state_store.py: Persists each scan as a timestamped snapshot in SQLite (scans, findings, certs tables)
- diff_engine.py: Compares the two most recent snapshots for a host, classifying each port as new / removed / changed / unchanged
- risk_scorer.py: Assigns a 0-10 risk score per finding, weighted by service type and change type (new exposures score highest)
- report.py: Renders the scored diff into a dark-themed HTML report with summary cards and tables
- monitor.py: Entry point, runs the entire pipeline against a target host

## Requirements

- Python 3.10+
- Nmap installed and on PATH
- A lab target to scan (tested against Metasploitable2 on an isolated
  host-only network — only scan hosts you own or are authorized to test)

## Setup

python3 -m venv venv
source venv/bin/activate
pip install python-nmap cryptography requests apscheduler jinja2

## Usage

Run the full pipeline against a target:

sudo $(pwd)/venv/bin/python3 monitor.py TARGET_IP

sudo is required because Nmap's version-detection scan needs elevated
privileges on most systems.

This will:
1. Scan the target with Nmap
2. Save the result as a new snapshot in data/snapshots.db
3. Diff it against the previous snapshot for that host
4. Score the changes by risk
5. Generate reports/latest.html

Open the report in a browser to see the results:

firefox reports/latest.html

## Example output

Running the tool twice, once as a baseline, once after stopping a service
on the target, correctly detects the service disappearing:

=== SUMMARY ===
New: 0
Removed: 1
Changed: 0
Unchanged: 22
Total risk score: 2.1
Report: ./reports/latest.html

## Risk scoring model

Each finding is scored on a 0-10 scale based on:
- Service type: e.g. telnet, bindshell, and shell score high by
  default; http/ssh score lower
- Change type: a new exposure is weighted highest (x1.5), a changed
  version is weighted neutrally (x1.0), and a removed service is weighted
  low (x0.3), since a shrinking attack surface is lower concern than a
  growing one

## Scope and limitations

- This is a detection and reporting tool only, it does not attempt
  exploitation of any kind.
- Designed and tested for a single-host lab environment; scanning multiple
  hosts or scheduling recurring scans would need light extension to
  monitor.py (e.g. looping over a target list, adding APScheduler).
- Risk scoring is a simple heuristic model, not tied to live CVE data (a
  natural next step would be querying NVD/OSV by service+version).

## Disclaimer

Only run this against systems you own or have explicit authorization to
test. Unauthorized scanning of systems you don't control may be illegal.
