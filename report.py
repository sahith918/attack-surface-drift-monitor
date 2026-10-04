"""
report.py

Generates an HTML report from a scored diff result (risk_scorer.score_diff output).
Uses Jinja2 with an inline template to keep everything in one file.
"""

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template


TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Attack Surface Drift Report — {{ host }}</title>
<style>
    body { font-family: -apple-system, Arial, sans-serif; background: #0f1117; color: #e6e6e6; margin: 0; padding: 2rem; }
    h1 { font-size: 1.4rem; margin-bottom: 0.2rem; }
    .meta { color: #999; margin-bottom: 1.5rem; }
    .summary { display: flex; gap: 1rem; margin-bottom: 2rem; }
    .card { background: #1a1d27; border-radius: 8px; padding: 1rem 1.5rem; flex: 1; }
    .card .num { font-size: 1.8rem; font-weight: bold; }
    .card .label { color: #999; font-size: 0.85rem; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
    th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #2a2d3a; font-size: 0.9rem; }
    th { color: #999; font-weight: normal; }
    .badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .CRITICAL { background: #4a1420; color: #ff6b81; }
    .HIGH { background: #4a2e14; color: #ffa94d; }
    .MEDIUM { background: #3a3a14; color: #f1e05a; }
    .LOW { background: #14301f; color: #69db7c; }
    .section-title { font-size: 1.1rem; margin: 2rem 0 0.75rem; }
    .empty { color: #666; font-style: italic; }
</style>
</head>
<body>

<h1>Attack Surface Drift Report</h1>
<div class="meta">Host: {{ host }} ({{ label }}) &nbsp;|&nbsp; Generated: {{ generated_at }}</div>

<div class="summary">
    <div class="card"><div class="num">{{ summary.counts.new }}</div><div class="label">New</div></div>
    <div class="card"><div class="num">{{ summary.counts.removed }}</div><div class="label">Removed</div></div>
    <div class="card"><div class="num">{{ summary.counts.changed }}</div><div class="label">Changed</div></div>
    <div class="card"><div class="num">{{ summary.counts.unchanged }}</div><div class="label">Unchanged</div></div>
    <div class="card"><div class="num">{{ summary.total_risk }}</div><div class="label">Total Risk Score</div></div>
</div>

<div class="section-title">New Exposures</div>
{% if new %}
<table>
<tr><th>Port</th><th>Service</th><th>Product/Version</th><th>Risk</th></tr>
{% for f in new %}
<tr>
    <td>{{ f.port }}/{{ f.protocol }}</td>
    <td>{{ f.service or '-' }}</td>
    <td>{{ f.product or '-' }} {{ f.version or '' }}</td>
    <td><span class="badge {{ f.risk_level }}">{{ f.risk_level }} ({{ f.risk_score }})</span></td>
</tr>
{% endfor %}
</table>
{% else %}
<div class="empty">No new ports/services since last scan.</div>
{% endif %}

<div class="section-title">Removed</div>
{% if removed %}
<table>
<tr><th>Port</th><th>Service</th><th>Product/Version</th><th>Risk</th></tr>
{% for f in removed %}
<tr>
    <td>{{ f.port }}/{{ f.protocol }}</td>
    <td>{{ f.service or '-' }}</td>
    <td>{{ f.product or '-' }} {{ f.version or '' }}</td>
    <td><span class="badge {{ f.risk_level }}">{{ f.risk_level }} ({{ f.risk_score }})</span></td>
</tr>
{% endfor %}
</table>
{% else %}
<div class="empty">Nothing closed since last scan.</div>
{% endif %}

<div class="section-title">Changed</div>
{% if changed %}
<table>
<tr><th>Port</th><th>Before</th><th>After</th><th>Risk</th></tr>
{% for c in changed %}
<tr>
    <td>{{ c.port }}/{{ c.protocol }}</td>
    <td>{{ c.before.product or c.before.service or '-' }} {{ c.before.version or '' }}</td>
    <td>{{ c.after.product or c.after.service or '-' }} {{ c.after.version or '' }}</td>
    <td><span class="badge {{ c.risk_level }}">{{ c.risk_level }} ({{ c.risk_score }})</span></td>
</tr>
{% endfor %}
</table>
{% else %}
<div class="empty">No version/service changes on existing ports.</div>
{% endif %}

<div class="section-title">Unchanged ({{ unchanged|length }})</div>
{% if unchanged %}
<table>
<tr><th>Port</th><th>Service</th><th>Product/Version</th></tr>
{% for f in unchanged %}
<tr>
    <td>{{ f.port }}/{{ f.protocol }}</td>
    <td>{{ f.service or '-' }}</td>
    <td>{{ f.product or '-' }} {{ f.version or '' }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<div class="empty">Nothing unchanged.</div>
{% endif %}

</body>
</html>
"""


def generate_report(host: str, label: str, scored_result: dict,
                     output_path: str = "./reports/latest.html") -> str:
    """
    Renders the scored diff result into an HTML file.
    Returns the output path.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    template = Template(TEMPLATE)
    html = template.render(
        host=host,
        label=label,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        new=scored_result["new"],
        removed=scored_result["removed"],
        changed=scored_result["changed"],
        unchanged=scored_result["unchanged"],
        summary=scored_result["summary"],
    )

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


if __name__ == "__main__":
    # Smoke test with fake scored data
    from risk_scorer import score_diff

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
            {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "4.7p1"},
        ],
    }

    scored = score_diff(fake_diff)
    path = generate_report("192.168.56.101", "metasploitable2", scored)
    print(f"Report written to {path}")
