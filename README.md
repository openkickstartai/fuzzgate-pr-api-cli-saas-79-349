# 🛡️ FuzzGate — Zero-Config API Fuzz Testing Engine

Find crashes, injections, and info leaks **before code merges**. One command. No security expertise required.

```bash
pip install -r requirements.txt
python fuzzgate.py api.yaml --base-url http://localhost:8000
```

## 🚀 Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Run against your API (free tier: SQLi + XSS + path traversal)
python fuzzgate.py openapi.yaml -u http://localhost:8000

# 3. Pro: all 5 attack categories + JSON report
python fuzzgate.py openapi.yaml -u http://localhost:8000 --pro -o report.json

# 4. CI: exits with code 1 if high-severity issues found
python fuzzgate.py openapi.yaml -u $API_URL --pro -o fuzzgate-report.json
```

## 🔍 What It Does

1. **Parses** your OpenAPI 3.x spec → extracts every endpoint & parameter
2. **Generates** thousands of malicious inputs (SQL injection, XSS, path traversal, integer overflow, oversized strings)
3. **Fires** fuzz requests and detects: 500 errors, timeouts, stack trace leaks, SQL error leaks, internal IP exposure
4. **Reports** with reproducible `curl` commands for every finding

## 💰 Pricing

| Feature | Free | Pro $79/mo | Team $199/mo | Enterprise $349/mo |
|---|---|---|---|---|
| Payload categories | 3 (SQLi, XSS, Path) | All 5 | All 5 | All 5 + custom |
| Endpoints per run | 5 | Unlimited | Unlimited | Unlimited |
| JSON report | ❌ | ✅ | ✅ | ✅ |
| CI integration | ❌ | ✅ GitHub/GitLab | ✅ + PR comments | ✅ + SARIF |
| PR comment reports | ❌ | ✅ | ✅ | ✅ |
| Dashboard & trends | ❌ | ❌ | ✅ | ✅ |
| Slack/PagerDuty | ❌ | ❌ | ✅ | ✅ |
| SOC2 evidence pack | ❌ | ❌ | ❌ | ✅ |
| SSO & self-hosted | ❌ | ❌ | ❌ | ✅ |

## 📊 Why Pay for FuzzGate?

| Traditional | FuzzGate |
|---|---|
| Pentest: $15k-50k/year, done once | $948-$4188/year, every PR |
| Burp Suite: needs security expert | `fuzzgate run` — any developer |
| Manual testing: misses edge cases | 1000+ payloads, automated |
| Find bugs in production | Find bugs before merge |

**ROI**: One prevented production incident pays for 3+ years of FuzzGate.

## 🏗️ Detection Capabilities

- **Server Errors**: Any 5xx response = likely unhandled input
- **Info Leaks**: Stack traces, SQL errors, internal IPs, path disclosure, debug info
- **Slow Responses**: >5s response = potential ReDoS or resource exhaustion
- **Crashes**: Connection failures after fuzz input = server crash

## License

BSL 1.1 — Free for small teams, paid license for commercial use.
