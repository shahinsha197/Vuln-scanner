"""
Passive Security Scanner — Engine
Performs all passive checks against a target URL.
No active exploitation — read-only HTTP requests only.
"""
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────────
# Vulnerability definitions with CVSS scores
# ─────────────────────────────────────────────
VULN_DEFINITIONS = {
    "missing_x_frame_options": {
        "name": "Missing X-Frame-Options Header",
        "cvss": 6.1,
        "severity": "Medium",
        "description": "The X-Frame-Options header is absent. Attackers can embed this page in an iframe to perform clickjacking attacks, tricking users into performing unintended actions.",
        "remediation": "Add `X-Frame-Options: DENY` or `SAMEORIGIN` to all HTTP responses.",
        "cwe": "CWE-1021",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "missing_csp": {
        "name": "Missing Content-Security-Policy Header",
        "cvss": 6.5,
        "severity": "Medium",
        "description": "No Content-Security-Policy (CSP) header was found. Without CSP, the browser permits loading resources from any origin, greatly increasing the risk of Cross-Site Scripting (XSS) attacks.",
        "remediation": "Define a strict CSP header, e.g., `Content-Security-Policy: default-src 'self'`.",
        "cwe": "CWE-693",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "missing_x_content_type": {
        "name": "Missing X-Content-Type-Options Header",
        "cvss": 5.3,
        "severity": "Medium",
        "description": "The X-Content-Type-Options header is missing. Browsers may MIME-sniff responses away from the declared content type, enabling certain injection attacks.",
        "remediation": "Add `X-Content-Type-Options: nosniff` to all HTTP responses.",
        "cwe": "CWE-693",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "missing_hsts": {
        "name": "Missing HTTP Strict-Transport-Security (HSTS)",
        "cvss": 7.4,
        "severity": "High",
        "description": "The Strict-Transport-Security header is not set. Without HSTS, browsers may connect over plain HTTP, exposing users to protocol downgrade and man-in-the-middle attacks.",
        "remediation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to HTTPS responses.",
        "cwe": "CWE-319",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "server_version_disclosure": {
        "name": "Server Version Disclosure",
        "cvss": 5.3,
        "severity": "Medium",
        "description": "The Server response header reveals the web server software and version. This helps attackers identify known vulnerabilities for the specific version in use.",
        "remediation": "Configure the web server to suppress or genericize the Server header (e.g., `Server: webserver`).",
        "cwe": "CWE-200",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "insecure_cookie": {
        "name": "Insecure Cookie Flags (Missing HttpOnly / Secure)",
        "cvss": 7.5,
        "severity": "High",
        "description": "One or more cookies are set without the HttpOnly or Secure flag. Without HttpOnly, JavaScript can access the cookie (enabling session theft via XSS). Without Secure, cookies are sent over plain HTTP.",
        "remediation": "Set `HttpOnly` and `Secure` flags on all sensitive cookies. Also consider adding `SameSite=Strict`.",
        "cwe": "CWE-614",
        "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute"
    },
    "sensitive_robots_txt": {
        "name": "Sensitive Paths Exposed in robots.txt",
        "cvss": 5.3,
        "severity": "Medium",
        "description": "The robots.txt file lists paths that appear to be sensitive (e.g., /admin, /backup, /config). While robots.txt is meant for search engine crawlers, it effectively acts as a roadmap for attackers.",
        "remediation": "Do not use robots.txt to hide sensitive endpoints. Protect them with authentication and authorization instead.",
        "cwe": "CWE-200",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "directory_listing": {
        "name": "Directory Listing Enabled",
        "cvss": 7.5,
        "severity": "High",
        "description": "A directory listing was detected, revealing the internal file structure. Attackers can browse and download sensitive files such as backups and configuration files.",
        "remediation": "Disable directory listing in your web server configuration (e.g., `Options -Indexes` in Apache).",
        "cwe": "CWE-548",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "sensitive_html_comment": {
        "name": "Sensitive Information in HTML Comments",
        "cvss": 4.3,
        "severity": "Medium",
        "description": "HTML source code contains comments with potentially sensitive information such as credentials, internal paths, or infrastructure details.",
        "remediation": "Remove all sensitive information from HTML comments before deploying to production. Use server-side comments instead.",
        "cwe": "CWE-615",
        "reference": "https://owasp.org/www-project-web-security-testing-guide/"
    },
    "outdated_js_library": {
        "name": "Outdated JavaScript Library Detected",
        "cvss": 6.1,
        "severity": "Medium",
        "description": "An outdated JavaScript library was detected in the page source. Old library versions often contain known security vulnerabilities that are publicly disclosed.",
        "remediation": "Update all JavaScript libraries to their latest stable versions. Consider using Subresource Integrity (SRI) hashes.",
        "cwe": "CWE-1035",
        "reference": "https://owasp.org/www-project-dependency-check/"
    }
}

# Known outdated JS library patterns (name, version regex, vulnerable if version < threshold)
OUTDATED_JS_PATTERNS = [
    (r'jquery[.-](\d+\.\d+\.?\d*)(\.min)?\.js', 'jQuery', '3.0.0'),
    (r'bootstrap[.-](\d+\.\d+\.?\d*)(\.min)?\.js', 'Bootstrap', '5.0.0'),
    (r'angular[.-](\d+\.\d+\.?\d*)(\.min)?\.js', 'AngularJS', '2.0.0'),
    (r'react[.-](\d+\.\d+\.?\d*)(\.min)?\.js', 'React', '16.0.0'),
    (r'vue[.-](\d+\.\d+\.?\d*)(\.min)?\.js', 'Vue.js', '3.0.0'),
]

SENSITIVE_PATH_KEYWORDS = [
    '/admin', '/backup', '/config', '/db', '/database',
    '/internal', '/private', '/secret', '/staging', '/test',
    '/dev', '/debug', '/api/internal', '/passwd', '/env'
]

SENSITIVE_COMMENT_PATTERNS = [
    r'password\s*[=:]\s*\S+',
    r'passwd\s*[=:]\s*\S+',
    r'pwd\s*[=:]\s*\S+',
    r'api[_\s]?key\s*[=:]\s*\S+',
    r'secret\s*[=:]\s*\S+',
    r'token\s*[=:]\s*\S+',
    r'admin\s*/\s*\S+',
    r'db[_\s]?pass',
    r'TODO.*admin',
    r'credentials',
    r'internal\.\w+\.\w+',   # internal domain pattern
]


def _version_lt(v1: str, v2: str) -> bool:
    """Returns True if v1 < v2 (simple version compare)."""
    try:
        parts1 = [int(x) for x in v1.split('.')]
        parts2 = [int(x) for x in v2.split('.')]
        for a, b in zip(parts1, parts2):
            if a < b:
                return True
            if a > b:
                return False
        return len(parts1) < len(parts2)
    except Exception:
        return False


def run_scan(url: str) -> dict:
    """
    Main entry point. Runs all passive checks against the given URL.
    Returns a dict with scan metadata and list of findings.
    """
    findings = []
    scan_meta = {
        "url": url,
        "status": "ok",
        "error": None,
        "pages_checked": [],
    }

    # ── Fetch the main page ──────────────────────────────────────────
    try:
        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": "PassiveScanner/1.0"})
    except requests.exceptions.ConnectionError:
        scan_meta["status"] = "error"
        scan_meta["error"] = "Could not connect to the target URL."
        return {"meta": scan_meta, "findings": [], "summary": _build_summary([])}
    except requests.exceptions.Timeout:
        scan_meta["status"] = "error"
        scan_meta["error"] = "Connection timed out."
        return {"meta": scan_meta, "findings": [], "summary": _build_summary([])}
    except Exception as e:
        scan_meta["status"] = "error"
        scan_meta["error"] = str(e)
        return {"meta": scan_meta, "findings": [], "summary": _build_summary([])}

    scan_meta["pages_checked"].append(url)
    headers = resp.headers
    html = resp.text
    soup = BeautifulSoup(html, 'html.parser')

    # ── Check 1: X-Frame-Options ─────────────────────────────────────
    if 'x-frame-options' not in {k.lower() for k in headers}:
        findings.append(_finding("missing_x_frame_options"))

    # ── Check 2: Content-Security-Policy ────────────────────────────
    if 'content-security-policy' not in {k.lower() for k in headers}:
        findings.append(_finding("missing_csp"))

    # ── Check 3: X-Content-Type-Options ─────────────────────────────
    if 'x-content-type-options' not in {k.lower() for k in headers}:
        findings.append(_finding("missing_x_content_type"))

    # ── Check 4: HSTS ────────────────────────────────────────────────
    if 'strict-transport-security' not in {k.lower() for k in headers}:
        findings.append(_finding("missing_hsts"))

    # ── Check 5: Server version disclosure ──────────────────────────
    server_hdr = headers.get('Server', headers.get('server', ''))
    if server_hdr and re.search(r'\d+\.\d+', server_hdr):
        f = _finding("server_version_disclosure")
        f["evidence"] = f"Server: {server_hdr}"
        findings.append(f)

    # ── Check 6: Insecure cookies ────────────────────────────────────
    set_cookie_headers = resp.headers.getlist('Set-Cookie') if hasattr(resp.headers, 'getlist') else []
    if not set_cookie_headers:
        raw_cookies = resp.headers.get('Set-Cookie', '')
        if raw_cookies:
            set_cookie_headers = [raw_cookies]

    insecure_cookies = []
    for cookie_str in set_cookie_headers:
        cookie_lower = cookie_str.lower()
        missing = []
        if 'httponly' not in cookie_lower:
            missing.append('HttpOnly')
        if 'secure' not in cookie_lower:
            missing.append('Secure')
        if missing:
            name = cookie_str.split('=')[0].strip()
            insecure_cookies.append(f"{name} (missing: {', '.join(missing)})")

    if insecure_cookies:
        f = _finding("insecure_cookie")
        f["evidence"] = "Insecure cookies: " + "; ".join(insecure_cookies)
        findings.append(f)

    # ── Check 7: robots.txt sensitive paths ──────────────────────────
    robots_url = urljoin(url, '/robots.txt')
    try:
        r_resp = requests.get(robots_url, timeout=5, verify=False,
                              headers={"User-Agent": "PassiveScanner/1.0"})
        scan_meta["pages_checked"].append(robots_url)
        if r_resp.status_code == 200:
            sensitive_found = [
                p for p in SENSITIVE_PATH_KEYWORDS
                if p.lower() in r_resp.text.lower()
            ]
            if sensitive_found:
                f = _finding("sensitive_robots_txt")
                f["evidence"] = "Sensitive paths in robots.txt: " + ", ".join(sensitive_found)
                findings.append(f)
    except Exception:
        pass

    # ── Check 8: Directory listing ───────────────────────────────────
    dir_listing_patterns = [
        r'Index of /',
        r'<title>Directory listing',
        r'Parent Directory</a>',
    ]
    # Check /backup/ as hinted by robots.txt findings
    for path in ['/backup/', '/files/', '/uploads/', '/static/']:
        try:
            d_url = urljoin(url, path)
            d_resp = requests.get(d_url, timeout=5, verify=False,
                                  headers={"User-Agent": "PassiveScanner/1.0"})
            scan_meta["pages_checked"].append(d_url)
            if d_resp.status_code == 200:
                for pattern in dir_listing_patterns:
                    if re.search(pattern, d_resp.text, re.IGNORECASE):
                        f = _finding("directory_listing")
                        f["evidence"] = f"Directory listing found at: {d_url}"
                        findings.append(f)
                        break
        except Exception:
            pass

    # ── Check 9: Sensitive HTML comments ────────────────────────────
    comments = soup.find_all(string=lambda t: isinstance(t, str) and '<!--' not in str(t))
    # Also get raw comment nodes
    from bs4 import Comment
    raw_comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    sensitive_comments = []
    for comment in raw_comments:
        for pattern in SENSITIVE_COMMENT_PATTERNS:
            if re.search(pattern, comment, re.IGNORECASE):
                snippet = comment.strip()[:120].replace('\n', ' ')
                sensitive_comments.append(snippet)
                break

    if sensitive_comments:
        f = _finding("sensitive_html_comment")
        f["evidence"] = "Found in HTML comment: " + " | ".join(sensitive_comments[:3])
        findings.append(f)

    # ── Check 10: Outdated JS libraries ─────────────────────────────
    page_text = html
    outdated_libs = []
    for pattern, lib_name, min_version in OUTDATED_JS_PATTERNS:
        matches = re.findall(pattern, page_text, re.IGNORECASE)
        for match in matches:
            version = match[0] if isinstance(match, tuple) else match
            if _version_lt(version, min_version):
                outdated_libs.append(f"{lib_name} v{version} (min safe: v{min_version})")

    if outdated_libs:
        f = _finding("outdated_js_library")
        f["evidence"] = "Outdated libraries: " + ", ".join(outdated_libs)
        findings.append(f)

    return {
        "meta": scan_meta,
        "findings": findings,
        "summary": _build_summary(findings)
    }


def _finding(vuln_id: str) -> dict:
    """Create a finding dict from a vulnerability definition."""
    defn = VULN_DEFINITIONS[vuln_id]
    return {
        "id": vuln_id,
        "name": defn["name"],
        "cvss": defn["cvss"],
        "severity": defn["severity"],
        "description": defn["description"],
        "remediation": defn["remediation"],
        "cwe": defn["cwe"],
        "reference": defn["reference"],
        "evidence": None,
    }


def _build_summary(findings: list) -> dict:
    """Build overall risk summary from findings."""
    if not findings:
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                "overall_score": 0.0, "overall_severity": "None"}

    scores = [f["cvss"] for f in findings]
    max_score = max(scores)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        s = f["severity"].lower()
        if s in counts:
            counts[s] += 1

    if max_score >= 9.0:
        overall = "Critical"
    elif max_score >= 7.0:
        overall = "High"
    elif max_score >= 4.0:
        overall = "Medium"
    elif max_score > 0:
        overall = "Low"
    else:
        overall = "None"

    return {
        "total": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "overall_score": round(max_score, 1),
        "overall_severity": overall,
    }
