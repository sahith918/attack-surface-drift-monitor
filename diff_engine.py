"""
diff_engine.py

Compares two snapshots (previous vs latest) for the same host and
classifies what changed: new ports, removed ports, and version/banner
changes on ports that stayed open.

This is the core "drift detection" logic of the project.
"""


def diff_snapshots(previous: dict | None, latest: dict) -> dict:
    """
    Compare two snapshots (as returned by state_store.get_last_two_scans)
    and return a structured diff:

        {
            "new": [finding, ...],       # ports open now, not open before
            "removed": [finding, ...],   # ports open before, not open now
            "changed": [{"port":, "before":, "after":}, ...],  # same port, different service/version
            "unchanged": [finding, ...], # same port, same service/version
        }

    If `previous` is None (first-ever scan for this host), everything in
    `latest` is treated as "new" — there's nothing to compare against yet.
    """
    if previous is None:
        return {
            "new": latest["findings"],
            "removed": [],
            "changed": [],
            "unchanged": [],
        }

    prev_by_port = {_port_key(f): f for f in previous["findings"]}
    latest_by_port = {_port_key(f): f for f in latest["findings"]}

    prev_ports = set(prev_by_port.keys())
    latest_ports = set(latest_by_port.keys())

    new_ports = latest_ports - prev_ports
    removed_ports = prev_ports - latest_ports
    common_ports = prev_ports & latest_ports

    new = [latest_by_port[p] for p in sorted(new_ports)]
    removed = [prev_by_port[p] for p in sorted(removed_ports)]

    changed = []
    unchanged = []
    for p in sorted(common_ports):
        before = prev_by_port[p]
        after = latest_by_port[p]
        if _findings_differ(before, after):
            changed.append({"port": p[0], "protocol": p[1],
                             "before": before, "after": after})
        else:
            unchanged.append(after)

    return {
        "new": new,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }


def _port_key(finding: dict) -> tuple:
    """Findings are matched by (port, protocol) — same port on tcp vs udp counts as different."""
    return (finding["port"], finding.get("protocol", "tcp"))


def _findings_differ(before: dict, after: dict) -> bool:
    """A finding counts as 'changed' if service, product, or version differs."""
    fields_to_compare = ("service", "product", "version")
    return any(before.get(f) != after.get(f) for f in fields_to_compare)


if __name__ == "__main__":
    # Quick smoke test using fake data
    previous = {
        "findings": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "product": "ProFTPD", "version": "1.3.1"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "4.7p1"},
            {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache", "version": "2.2.8"},
        ]
    }
    latest = {
        "findings": [
            {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "4.7p1"},
            {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache", "version": "2.4.1"},  # version bumped
            {"port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "Squid", "version": "3.1"},  # new
        ]
    }

    result = diff_snapshots(previous, latest)
    print("NEW:", result["new"])
    print("REMOVED:", result["removed"])
    print("CHANGED:", result["changed"])
    print("UNCHANGED:", result["unchanged"])
