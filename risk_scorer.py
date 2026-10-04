"""
risk_scorer.py

Assigns a risk score to each item in a diff result. The scoring logic:

  - Change type matters: a NEW exposed port is more concerning than a
    REMOVED one (attack surface growing vs shrinking).
  - Service type matters: some services are inherently higher-risk if
    exposed (e.g. telnet, unauthenticated shells, old SMB) vs lower-risk
    (e.g. a well-known web port).
  - Combined into one weighted score per finding, plus an overall
    snapshot-level summary.
"""

# Baseline risk by service — rough, illustrative severity on a 1-10 scale.
# Services not listed default to MEDIUM_DEFAULT.
SERVICE_RISK = {
    "telnet": 9,
    "ftp": 7,
    "rexec": 9,
    "exec": 9,
    "login": 8,
    "shell": 9,
    "bindshell": 10,
    "irc": 6,
    "vnc": 8,
    "netbios-ssn": 7,
    "rpcbind": 6,
    "nfs": 6,
    "mysql": 6,
    "postgresql": 6,
    "java-rmi": 6,
    "ajp13": 5,
    "http": 4,
    "https": 3,
    "ssh": 3,
    "domain": 3,
    "smtp": 4,
}
MEDIUM_DEFAULT = 5

# Multiplier based on what kind of change this is
CHANGE_TYPE_WEIGHT = {
    "new": 1.5,        # new exposure — most concerning
    "changed": 1.0,    # version/service change — worth reviewing
    "removed": 0.3,    # attack surface shrinking — low concern, still logged
}


def score_finding(finding: dict, change_type: str) -> dict:
    """
    Score a single finding. Returns the finding plus a 'risk_score' field
    (0-10 scale) and a 'risk_level' label.
    """
    service = (finding.get("service") or "").lower()
    base = SERVICE_RISK.get(service, MEDIUM_DEFAULT)
    weight = CHANGE_TYPE_WEIGHT.get(change_type, 1.0)

    score = round(min(base * weight, 10), 1)

    return {
        **finding,
        "change_type": change_type,
        "risk_score": score,
        "risk_level": _risk_level(score),
    }


def _risk_level(score: float) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def score_diff(diff: dict) -> dict:
    """
    Takes a diff_engine.diff_snapshots() result and returns a scored version:
        {
            "new": [scored finding, ...],
            "removed": [scored finding, ...],
            "changed": [scored change, ...],
            "unchanged": [...],   # left as-is, not scored
            "summary": {"total_risk": float, "highest": scored finding or None, "counts": {...}}
        }
    """
    scored_new = [score_finding(f, "new") for f in diff["new"]]
    scored_removed = [score_finding(f, "removed") for f in diff["removed"]]

    scored_changed = []
    for c in diff["changed"]:
        scored_after = score_finding(c["after"], "changed")
        scored_changed.append({**c, "risk_score": scored_after["risk_score"],
                                "risk_level": scored_after["risk_level"]})

    all_scored = scored_new + scored_removed + scored_changed
    total_risk = round(sum(f["risk_score"] for f in all_scored), 1)
    highest = max(all_scored, key=lambda f: f["risk_score"], default=None)

    counts = {
        "new": len(scored_new),
        "removed": len(scored_removed),
        "changed": len(scored_changed),
        "unchanged": len(diff["unchanged"]),
    }

    return {
        "new": scored_new,
        "removed": scored_removed,
        "changed": scored_changed,
        "unchanged": diff["unchanged"],
        "summary": {
            "total_risk": total_risk,
            "highest": highest,
            "counts": counts,
        },
    }


if __name__ == "__main__":
    # Smoke test using the same fake diff shape as diff_engine.py's test
    fake_diff = {
        "new": [
            {"port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd", "version": None},
        ],
        "removed": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "product": "ProFTPD", "version": "1.3.1"},
        ],
        "changed": [
            {"port": 80, "protocol": "tcp",
             "before": {"service": "http", "version": "2.2.8"},
             "after": {"service": "http", "version": "2.4.1"}},
        ],
        "unchanged": [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
        ],
    }

    result = score_diff(fake_diff)
    print("NEW:", result["new"])
    print("REMOVED:", result["removed"])
    print("CHANGED:", result["changed"])
    print("SUMMARY:", result["summary"])
