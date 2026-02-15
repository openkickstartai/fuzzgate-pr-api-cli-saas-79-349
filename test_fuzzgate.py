"""Tests for FuzzGate — API fuzz testing engine."""
import json
import pytest
import yaml
from pathlib import Path
from fuzzgate import parse_openapi, detect_issues, build_curl
from payloads import get_all_payloads, get_free_payloads, PAYLOADS, LEAK_PATTERNS

SAMPLE_SPEC = {
    "openapi": "3.0.0", "info": {"title": "Test", "version": "1.0"}, "paths": {
        "/users": {
            "get": {"parameters": [{"name": "q", "in": "query"}]},
            "post": {"requestBody": {"content": {"application/json": {
                "schema": {"properties": {"name": {"type": "string"},
                                           "email": {"type": "string"}}}}}}},
        },
        "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
    }
}


@pytest.fixture
def spec_file(tmp_path):
    p = tmp_path / "api.yaml"
    p.write_text(yaml.dump(SAMPLE_SPEC))
    return str(p)


class TestParseOpenAPI:
    def test_finds_all_endpoints(self, spec_file):
        eps = parse_openapi(spec_file)
        assert len(eps) == 3

    def test_correct_methods(self, spec_file):
        eps = parse_openapi(spec_file)
        assert sorted(e["method"] for e in eps) == ["GET", "GET", "POST"]

    def test_query_param(self, spec_file):
        eps = parse_openapi(spec_file)
        get_ep = [e for e in eps if e["path"] == "/users" and e["method"] == "GET"][0]
        assert get_ep["params"] == [{"name": "q", "in": "query"}]

    def test_body_params(self, spec_file):
        eps = parse_openapi(spec_file)
        post_ep = [e for e in eps if e["method"] == "POST"][0]
        assert {p["name"] for p in post_ep["params"]} == {"name", "email"}

    def test_path_param(self, spec_file):
        eps = parse_openapi(spec_file)
        path_ep = [e for e in eps if "{id}" in e["path"]][0]
        assert path_ep["params"][0] == {"name": "id", "in": "path"}


class TestDetectIssues:
    def test_500_high_severity(self):
        issues = detect_issues(500, "error", 100)
        assert len(issues) == 1
        assert issues[0]["type"] == "server_error"
        assert issues[0]["severity"] == "high"

    def test_clean_200(self):
        assert detect_issues(200, '{"ok": true}', 50) == []

    def test_stack_trace_leak(self):
        issues = detect_issues(200, "Traceback (most recent call last):\n  File", 50)
        assert any(i["detail"] == "stack_trace" for i in issues)

    def test_sql_error_leak(self):
        issues = detect_issues(200, "error in your SQL syntax near", 50)
        assert any(i["detail"] == "sql_error" for i in issues)

    def test_internal_ip_leak(self):
        issues = detect_issues(200, "connecting to 10.0.1.55:5432", 50)
        assert any(i["detail"] == "internal_ip" for i in issues)

    def test_slow_response(self):
        issues = detect_issues(200, "ok", 6000)
        assert issues[0]["type"] == "slow_response"
        assert issues[0]["severity"] == "medium"

    def test_multiple_issues(self):
        body = "Traceback: mysql_fetch error at 10.0.0.1"
        issues = detect_issues(500, body, 6000)
        types = {i["type"] for i in issues}
        assert "server_error" in types and "info_leak" in types and "slow_response" in types


class TestBuildCurl:
    def test_query_curl(self):
        curl = build_curl("http://x", {"method": "GET", "path": "/s"}, {"name": "q", "in": "query"}, "t")
        assert curl == 'curl -X GET "http://x/s?q=t"'

    def test_body_curl(self):
        curl = build_curl("http://x", {"method": "POST", "path": "/u"}, {"name": "n", "in": "body"}, "v")
        assert "POST" in curl and "Content-Type" in curl and '"n"' in curl

    def test_path_curl(self):
        curl = build_curl("http://x", {"method": "GET", "path": "/u/{id}"}, {"name": "id", "in": "path"}, "42")
        assert "/u/42" in curl and "{id}" not in curl


class TestPayloads:
    def test_all_5_categories(self):
        assert set(get_all_payloads().keys()) == {"sqli", "xss", "path_traversal", "integer_boundary", "oversized"}

    def test_free_3_categories(self):
        free = get_free_payloads()
        assert len(free) == 3
        assert "integer_boundary" not in free and "oversized" not in free

    def test_min_payloads_per_category(self):
        for cat, vals in get_all_payloads().items():
            assert len(vals) >= 6, f"{cat} has only {len(vals)} payloads"

    def test_sqli_has_quotes(self):
        assert any("'" in str(p) for p in PAYLOADS["sqli"])

    def test_xss_has_script_tags(self):
        assert any("<script" in str(p) for p in PAYLOADS["xss"])

    def test_leak_patterns_compile(self):
        import re
        for name, pat in LEAK_PATTERNS.items():
            compiled = re.compile(pat, re.IGNORECASE)
            assert compiled is not None, f"Pattern {name} failed to compile"
