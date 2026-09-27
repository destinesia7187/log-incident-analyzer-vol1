"""Safe, self-contained reports. Evidence values are never template code."""

from __future__ import annotations

import hashlib
import hmac
import html
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, StrictUndefined

from .common import terminal_safe, utc_text, write_json

HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>Log Incident Analyzer — investigation report</title>
<style>body{font:16px/1.6 system-ui,sans-serif;background:#f2f5f8;color:#172b3a;margin:0}main{max-width:1100px;margin:auto;padding:32px}h1{font-size:2.4rem;line-height:1.15}h2{margin-top:32px}article{background:white;padding:24px;margin:24px 0;border:1px solid #cad6df;border-radius:12px}a{color:#005b9a}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:8px;border-bottom:1px solid #cad6df;overflow-wrap:anywhere}th{background:#e8eff5}code{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef3f6;padding:16px}.muted{color:#405564}.badge{font-weight:700}.fact{border-left:4px solid #006d77;padding-left:16px}@media print{body{background:white}article{break-inside:avoid}main{padding:0}}</style></head>
<body><main><p class="muted">LOCAL ANALYSIS · Evidence-based triage</p><h1>Investigation report</h1>
<p>{{ analysis.cases|length }} cases · {{ analysis.alerts|length }} alerts · {{ analysis.event_count }} accepted events</p>
<p>Rule matches require human review. Missing observations do not establish safety.</p>
<nav aria-label="Cases"><h2>Cases</h2><ul>{% for c in analysis.cases %}<li><a href="#{{c.id}}">{{c.priority|upper}} · {{c.title}} · {{c.id}}</a></li>{% endfor %}</ul></nav>
<h2>Telemetry readiness</h2><div style="overflow-x:auto"><table><thead><tr><th>Rule</th><th>Status</th><th>Eligible / candidates</th><th>Missing fields</th></tr></thead><tbody>{% for q in analysis.quality %}<tr><td>{{q.rule_id}}</td><td>{{q.status.replace('_', ' ')}}</td><td>{{q.eligible}} / {{q.candidates}}</td><td>{% for field, count in q.missing_fields.items() %}{{field}}: {{count}}{% if not loop.last %}; {% endif %}{% else %}None{% endfor %}</td></tr>{% endfor %}</tbody></table></div>
{% for c in analysis.cases %}<article id="{{c.id}}"><p class="badge">{{c.priority|upper}} · {{c.status}} · {{c.decision}}</p><h2>{{c.title}}</h2><code>{{c.id}}</code>
<p>{{utc(c.start)}} — {{utc(c.end)}} · User: {{c.user_id}} · Source: {{c.client_ip}}</p><h3>Priority</h3><p>Score: {{c.score}} / 100</p><ul>{% for item in c.score_components %}<li>{{item.reason.replace('_', ' ')|capitalize}}: {{item.value}}</li>{% endfor %}</ul><p>Evidence confidence: {{c.confidence}}. {{c.confidence_reasons|join(' ')}}</p>
<h3>Facts and evidence</h3>{% for f in c.facts %}<p class="fact">{{f.text}} <small>({{f.evidence_ids|length}} supporting events)</small></p>{% endfor %}
<h3>Hypotheses</h3><ul>{% for text in c.hypotheses %}<li>{{text}}</li>{% endfor %}</ul><h3>Alternative explanations</h3><ul>{% for text in c.alternatives %}<li>{{text}}</li>{% endfor %}</ul>
<h3>Limitations</h3><ul>{% for text in c.limitations %}<li>{{text}}</li>{% endfor %}</ul><h3>Next checks</h3><ul>{% for text in c.next_steps %}<li>{{text}}</li>{% endfor %}</ul>
<h3>ATT&amp;CK candidates</h3><ul>{% for m in c.attack %}<li>{{m.technique_id}} — {{m.mapping_status}}: {{m.rationale}}</li>{% endfor %}</ul>
<h3>Timeline</h3><p>{{c.evidence_ids|length}} evidence events. {% if c.evidence_ids|length > 50 %}Card truncated to 50; full evidence is in analysis.json and analysis.sqlite.{% endif %}</p>
<div style="overflow-x:auto"><table style="min-width:620px"><thead><tr><th>UTC</th><th>Action / outcome</th><th>Source line</th><th>Evidence ID</th></tr></thead><tbody>{% for e in timelines[c.id] %}<tr><td>{{utc(e.time)}}</td><td>{{e.fields['event.action']}} / {{e.fields['event.outcome']}}</td><td>{{e.source_id}}:{{e.line}}</td><td><abbr title="{{e.uid}}">{{e.uid[:16]}}…</abbr></td></tr>{% endfor %}</tbody></table></div>
<h3>Analyst notes</h3><ul>{% for n in c.notes %}<li>{{n.analyst}}: {{n.text}}</li>{% else %}<li>No analyst notes.</li>{% endfor %}</ul><h3>Context</h3><ul>{% for context in c.get('context_details', []) %}<li>{{context.kind}} · {{context.id}}: {{context.reason}} ({{context.author}}, {{context.source}}; {{context.valid_from}} — {{context.expires_at}})</li>{% else %}<li>No context details in this export.</li>{% endfor %}</ul><p>Suppressed: {{'yes' if c.suppressed else 'no'}}</p></article>{% endfor %}
</main></body></html>"""


def md_escape(value: Any) -> str:
    text = html.escape(terminal_safe(str(value)), quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text).replace("\n", " ")


def markdown(analysis: dict) -> str:
    rows = [
        "# Log Incident Analyzer — investigation report",
        "",
        f"Cases: {len(analysis['cases'])} · Alerts: {len(analysis['alerts'])} · Events: {analysis['event_count']}",
        "",
        "Rule matches require analyst review. Missing observations do not establish safety.",
        "",
        "## Telemetry",
        "",
        "| Rule | Status | Eligible / candidates |",
        "|---|---|---|",
    ]
    for q in analysis["quality"]:
        rows.append(
            f"| {md_escape(q['rule_id'])} | {md_escape(q['status'])} | {q['eligible']} / {q['candidates']} |"
        )
    for c in analysis["cases"]:
        rows.extend(
            [
                "",
                "## " + md_escape(c["title"]),
                "",
                f"**{c['priority'].upper()} · {c['decision']}** · {c['id']}",
                "",
                f"UTC: {utc_text(c['start'])} — {utc_text(c['end'])}",
                "",
                f"User: {md_escape(c['user_id'])}; source: {md_escape(c['client_ip'])}",
                "",
                f"Score: {c['score']} · Evidence confidence: {c['confidence']}",
                f"Status: {c['status']}",
                "",
            ]
        )
        rows.extend(
            "- " + md_escape(item["reason"].replace("_", " ")) + ": " + str(item["value"])
            for item in c["score_components"]
        )
        rows.extend(
            ["", "### ATT&CK candidates", ""]
            + [
                "- " + md_escape(m["technique_id"] + ": " + m["mapping_status"] + ". " + m["rationale"])
                for m in c["attack"]
            ]
            + [""]
        )
        rows.extend(
            ["### Context", ""]
            + [
                "- "
                + md_escape(
                    context["id"]
                    + ": "
                    + context["reason"]
                    + " ("
                    + context["author"]
                    + ", "
                    + context["source"]
                    + ")"
                )
                for context in c.get("context_details", [])
            ]
            + [""]
        )
        for heading, texts in [
            ("Facts", [f["text"] for f in c["facts"]]),
            ("Hypotheses", c["hypotheses"]),
            ("Alternative explanations", c["alternatives"]),
            ("Limitations", c["limitations"]),
            ("Next checks", c["next_steps"]),
        ]:
            rows.extend(["### " + heading, ""] + ["- " + md_escape(t) for t in texts] + [""])
        rows.extend(
            [
                "### Evidence",
                "",
                f"{len(c['evidence_ids'])} events. Full records: analysis.json / analysis.sqlite.",
                "",
            ]
        )
        rows.extend("- " + uid for uid in c["evidence_ids"][:50])
        if len(c["evidence_ids"]) > 50:
            rows.append("- Card truncated to 50 events.")
        rows.extend(
            ["", "### Analyst notes", ""]
            + ["- " + md_escape(n["analyst"]) + ": " + md_escape(n["text"]) for n in c["notes"]]
        )
    return "\n".join(rows) + "\n"


def shareable(analysis: dict, key: bytes) -> dict:
    sensitive = {
        "user_id",
        "client_ip",
        "actor.user_id",
        "target.user_id",
        "network.client_ip",
        "network.peer_ip",
        "auth.device_ref",
        "auth.session_ref",
        "target.resource_id",
        "source_id",
        "tenant_id",
        "application_id",
        "tenant.id",
        "app.id",
        "event.original_id",
        "http.request_id",
        "auth.mfa_request_id",
    }

    def token(value: str) -> str:
        return "ref-" + hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:20]

    replacements: dict[str, str] = {}

    def collect(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in sensitive and isinstance(v, str):
                    replacements[v] = token(v)
                collect(v)
        elif isinstance(obj, list):
            for item in obj:
                collect(item)

    collect(analysis)

    def walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                k: walk(v)
                for k, v in obj.items()
                if k not in {"offset", "path", "input_root", "notes", "history", "context_details"}
            } | ({"notes": [], "history": []} if "notes" in obj else {})
        if isinstance(obj, list):
            return [walk(v) for v in obj]
        if isinstance(obj, str):
            return replacements.get(obj, obj)
        return obj

    result = walk(analysis)
    result["shareable"] = True
    return result


def export(analysis: dict, directory: Path, formats: list[str]) -> None:
    write_json(directory / "analysis.json", analysis)
    write_json(
        directory / "quality.json",
        {"schema_version": "1.0", "rules": analysis["quality"], "findings": analysis["quality_findings"]},
    )
    if "markdown" in formats:
        (directory / "report.md").write_text(markdown(analysis), encoding="utf-8")
    if "html" in formats:
        env = Environment(autoescape=True, undefined=StrictUndefined)
        env.globals["utc"] = utc_text
        evidence = {e["uid"]: e for e in analysis["evidence"]}
        timelines = {
            c["id"]: sorted(
                (evidence[uid] for uid in c["evidence_ids"]), key=lambda e: (e["time"], e["uid"])
            )[:50]
            for c in analysis["cases"]
        }
        (directory / "report.html").write_text(
            env.from_string(HTML).render(analysis=analysis, timelines=timelines), encoding="utf-8"
        )
