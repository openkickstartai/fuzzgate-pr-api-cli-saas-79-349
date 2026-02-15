#!/usr/bin/env python3
"""FuzzGate CLI — Zero-config API fuzz testing engine."""
import sys
import click
import json
import re
import time
import yaml
import requests
from pathlib import Path
from payloads import get_all_payloads, get_free_payloads, LEAK_PATTERNS


def parse_openapi(spec_path):
    """Parse OpenAPI 3.x spec, return list of endpoint dicts."""
    spec = yaml.safe_load(Path(spec_path).read_text())
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, detail in methods.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            params = [{"name": p["name"], "in": p.get("in", "query")}
                      for p in detail.get("parameters", [])]
            for _, ct in detail.get("requestBody", {}).get("content", {}).items():
                for prop in ct.get("schema", {}).get("properties", {}):
                    params.append({"name": prop, "in": "body"})
            endpoints.append({"path": path, "method": method.upper(), "params": params})
    return endpoints


def detect_issues(status, body, elapsed_ms):
    """Detect server errors, slow responses, and information leaks."""
    issues = []
    if status >= 500:
        issues.append({"type": "server_error", "severity": "high", "detail": f"HTTP {status}"})
    if elapsed_ms > 5000:
        issues.append({"type": "slow_response", "severity": "medium", "detail": f"{elapsed_ms}ms"})
    for name, pat in LEAK_PATTERNS.items():
        if re.search(pat, body, re.IGNORECASE):
            issues.append({"type": "info_leak", "severity": "high", "detail": name})
    return issues


def build_curl(base_url, ep, param, payload):
    """Generate a reproducible curl command for a finding."""
    url = base_url.rstrip("/") + ep["path"]
    val = str(payload)[:200]
    if param["in"] == "query":
        return f'curl -X {ep["method"]} "{url}?{param["name"]}={val}"'
    if param["in"] == "body":
        d = json.dumps({param["name"]: val})
        return f"curl -X {ep['method']} '{url}' -H 'Content-Type: application/json' -d '{d}'"
    return f'curl -X {ep["method"]} "{url.replace("{" + param["name"] + "}", val)}"'


def fuzz(base_url, endpoints, payloads, timeout=10):
    """Fire fuzz payloads at all endpoints, return list of findings."""
    findings = []
    for ep in endpoints:
        for param in ep["params"]:
            for cat, values in payloads.items():
                for payload in values:
                    url = base_url.rstrip("/") + ep["path"]
                    kw = {"timeout": timeout}
                    if param["in"] == "query":
                        kw["params"] = {param["name"]: payload}
                    elif param["in"] == "body":
                        kw["json"] = {param["name"]: payload}
                    else:
                        url = url.replace("{" + param["name"] + "}", str(payload))
                    try:
                        t0 = time.time()
                        r = requests.request(ep["method"], url, **kw)
                        ms = int((time.time() - t0) * 1000)
                        for issue in detect_issues(r.status_code, r.text, ms):
                            finding = {"endpoint": f'{ep["method"]} {ep["path"]}',
                                       "parameter": param["name"], "category": cat,
                                       "payload": str(payload)[:100],
                                       "curl": build_curl(base_url, ep, param, payload)}
                            finding.update(issue)
                            findings.append(finding)
                    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                        findings.append({"endpoint": f'{ep["method"]} {ep["path"]}',
                                         "parameter": param["name"], "category": cat,
                                         "payload": str(payload)[:100], "type": "crash_or_timeout",
                                         "severity": "high", "detail": type(e).__name__,
                                         "curl": build_curl(base_url, ep, param, payload)})
    return findings


@click.command()
@click.argument("spec_path")
@click.option("--base-url", "-u", required=True, help="API base URL")
@click.option("--output", "-o", default=None, help="JSON report output path")
@click.option("--timeout", "-t", default=10, type=int, help="Request timeout (seconds)")
@click.option("--pro", is_flag=True, help="Unlock all 5 payload categories")
def main(spec_path, base_url, output, timeout, pro):
    """FuzzGate — Zero-config API fuzz testing."""
    endpoints = parse_openapi(spec_path)
    payloads = get_all_payloads() if pro else get_free_payloads()
    total = sum(len(v) for v in payloads.values())
    params = sum(len(e["params"]) for e in endpoints)
    click.echo(f"\U0001f50d {len(endpoints)} endpoints, {params} params, {total} payloads")
    findings = fuzz(base_url, endpoints, payloads, timeout)
    high = sum(1 for f in findings if f["severity"] == "high")
    if findings:
        click.echo(f"\n\U0001f6a8 {len(findings)} issues ({high} high):\n")
        for f in findings:
            icon = "\U0001f534" if f["severity"] == "high" else "\U0001f7e1"
            click.echo(f'{icon} [{f["type"]}] {f["endpoint"]} | {f["parameter"]} ({f["category"]})')
            click.echo(f'   {f["detail"]}')
            click.echo(f'   {f["curl"]}\n')
    else:
        click.echo("\n\u2705 No issues found!")
    if output:
        report = {"findings": findings, "summary": {"total": len(findings), "high": high,
                  "endpoints_tested": len(endpoints), "params_tested": params}}
        Path(output).write_text(json.dumps(report, indent=2, default=str))
        click.echo(f"\U0001f4c4 Report saved: {output}")
    sys.exit(1 if high > 0 else 0)


if __name__ == "__main__":
    main()
