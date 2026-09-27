"""Capture six actual HTTP workflows against a disposable loopback-only audit app.

The server is deliberately small, uses synthetic identities and writes no credentials.
It demonstrates instrumentation, not a production identity provider or exploit lab.
"""

from __future__ import annotations

import argparse
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from lia.common import write_json
from lia.demo import write_input
from lia.pipeline import analyze


def capture(output: Path) -> dict:
    if output.exists():
        raise ValueError("Choose a new lab output directory")
    rows: list[dict] = []
    sessions: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            actor = body.get("user", "lab-owner")
            event = {
                "schema_version": "app-audit-v1",
                "event_id": f"lab-{len(rows):05}",
                "timestamp": datetime.now(UTC).isoformat(timespec="microseconds"),
                "actor": {"user_id": actor},
                "network": {"peer_ip": self.client_address[0]},
            }
            status, payload = 403, {}
            if self.path == "/login":
                success = body.get("test_code") == "synthetic-correct-code"
                event.update(action="auth.login", outcome="success" if success else "failure")
                if success:
                    ref = f"lab-session-{len(rows)}"
                    sessions[ref] = actor
                    event["auth"] = {"session_ref": ref}
                    payload = {"session": ref}
                    status = 200
            elif self.path == "/mfa/enroll" and sessions.get(body.get("session")) == actor:
                event.update(action="auth.mfa.enroll", outcome="success")
                event["target"] = {"user_id": actor}
                event["auth"] = {"session_ref": body["session"], "device_ref": "lab-device-2"}
                status = 200
            elif self.path == "/resource":
                event.update(action="authz.check", outcome="denied")
                event["target"] = {"resource_id": body["resource"]}
            else:
                self.send_error(404)
                return
            rows.append(event)
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def request(endpoint: str, **body):
        req = Request(
            f"http://127.0.0.1:{server.server_port}{endpoint}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=5) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code != 403:
                raise
            return {}

    definitions = [
        ("attack-login-mfa", "attack", {"DET-001", "DET-003", "DET-006"}),
        ("attack-spray", "attack", {"DET-002"}),
        ("attack-authorization", "attack", {"DET-008"}),
        ("benign-login", "benign", set()),
        ("benign-owner-errors", "benign", {"DET-001"}),
        ("benign-mfa-maintenance", "benign", set()),
    ]
    results = []
    try:
        for name, label, expected in definitions:
            rows.clear()
            sessions.clear()
            if name in {"attack-login-mfa", "benign-owner-errors"}:
                for _ in range(10):
                    request("/login", user="lab-owner", test_code="synthetic-wrong-code")
            if name in {"attack-login-mfa", "benign-login", "benign-mfa-maintenance"}:
                session = request("/login", user="lab-owner", test_code="synthetic-correct-code")["session"]
                if name != "benign-login":
                    request("/mfa/enroll", user="lab-owner", session=session)
            if name == "attack-spray":
                for i in range(10):
                    request("/login", user=f"lab-user-{i}", test_code="synthetic-wrong-code")
            if name == "attack-authorization":
                for i in range(10):
                    request("/resource", user="lab-owner", resource=f"private-{i % 3}")
            manifest = write_input(output / "captures" / name, rows)
            analysis, _, code = analyze(manifest, output / "analysis" / name)
            observed = {a["rule_id"] for a in analysis["alerts"]}
            results.append(
                {
                    "scenario": name,
                    "label": label,
                    "requests": len(rows),
                    "expected_rules": sorted(expected),
                    "observed_rules": sorted(observed),
                    "passed": expected == observed and code == 0,
                    "false_positive_expected": name == "benign-owner-errors",
                }
            )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    report = {
        "origin": "HTTP requests recorded by tools/capture_lab.py on 127.0.0.1",
        "scope": "Toy application with synthetic identities; not a production IdP validation",
        "captured_at": datetime.now(UTC).isoformat(),
        "scenarios": results,
        "passed": all(r["passed"] for r in results),
    }
    write_json(output / "lab-report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = capture(args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
