import requests
import time
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
import argparse
import os


RATE_LIMIT_DELAY = 1  # seconds delay between requests

# Common sensitive paths and admin panels to check
SENSITIVE_PATHS = [
    "/admin", "/login", "/wp-admin", "/user", "/dashboard", "/config", "/.git"
]

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

OPEN_REDIRECT_TESTS = [
    "/?redirect=http://example.com",
    "/?url=http://example.com",
    "/?next=http://example.com",
]

def is_live(url):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        return r.status_code < 400
    except requests.RequestException:
        return False

def check_security_headers(url):
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        return missing
    except requests.RequestException:
        return SECURITY_HEADERS[:]  # Assume all missing if request fails

def check_sensitive_paths(base_url):
    found = []
    for path in SENSITIVE_PATHS:
        test_url = urljoin(base_url, path)
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code < 400:
                found.append(test_url)
            time.sleep(RATE_LIMIT_DELAY)
        except requests.RequestException:
            pass
    return found

def check_admin_panels(base_url):
    # Overlaps with sensitive paths but more specific
    admin_paths = ["/admin", "/login.php", "/admin.php", "/login", "/administrator"]
    found = []
    for path in admin_paths:
        test_url = urljoin(base_url, path)
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code < 400:
                found.append(test_url)
            time.sleep(RATE_LIMIT_DELAY)
        except requests.RequestException:
            pass
    return found

def check_cors_misconfig(url):
    try:
        r = requests.get(url, timeout=5)
        origin = r.request.headers.get("Origin")
        ac_allow_origin = r.headers.get("Access-Control-Allow-Origin")
        ac_allow_credentials = r.headers.get("Access-Control-Allow-Credentials")
        # Basic check: if ACAO is "*" and credentials allowed => misconfig
        if ac_allow_origin == "*" and ac_allow_credentials == "true":
            return "Wildcard ACAO with credentials allowed (bad)"
        return None
    except requests.RequestException:
        return None

def check_open_redirects(base_url):
    found = []
    for test_path in OPEN_REDIRECT_TESTS:
        test_url = urljoin(base_url, test_path)
        try:
            r = requests.get(test_url, timeout=5, allow_redirects=False)
            if r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get("Location", "")
                if "example.com" in location:
                    found.append(test_url)
            time.sleep(RATE_LIMIT_DELAY)
        except requests.RequestException:
            pass
    return found

def check_sql_injection(url):
    vulnerable_urls = []
    payloads = ["' OR '1'='1", '" OR 1=1 -- ']
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return []
    for param in query_params:
        for payload in payloads:
            injected_params = query_params.copy()
            injected_params[param] = payload
            injected_query = "&".join([f"{k}={v}" for k,v in injected_params.items()])
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{injected_query}"
            try:
                r = requests.get(test_url, timeout=5)
                # Check for common SQL error indicators in response
                if r.status_code == 200 and any(err in r.text.lower() for err in ["mysql", "syntax", "error", "sql"]):
                    vulnerable_urls.append(test_url)
                time.sleep(RATE_LIMIT_DELAY)
            except requests.RequestException:
                pass
    return vulnerable_urls

def check_xss(url):
    vulnerable_urls = []
    xss_payload = "<script>alert(1)</script>"
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return []
    for param in query_params:
        injected_params = query_params.copy()
        injected_params[param] = xss_payload
        injected_query = "&".join([f"{k}={v}" for k,v in injected_params.items()])
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{injected_query}"
        try:
            r = requests.get(test_url, timeout=5)
            if xss_payload in r.text:
                vulnerable_urls.append(test_url)
            time.sleep(RATE_LIMIT_DELAY)
        except requests.RequestException:
            pass
    return vulnerable_urls

def check_ssl_info(domain):
    cert_info = {}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                not_after = cert['notAfter']
                cert_info['issuer'] = issuer.get('organizationName', 'Unknown')
                cert_info['expiry'] = not_after
    except Exception:
        cert_info = None
    return cert_info

def generate_report(results, filename, format="txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if format.lower() == "html":
        content = f"<html><head><title>Bug Bounty Report - {results['target']}</title></head><body>"
        content += f"<h1>Bug Bounty Scan Report for {results['target']}</h1>"
        content += f"<p>Scan Timestamp: {timestamp}</p>"

        content += f"<h2>Scan Results</h2>"
        content += f"<p>Live: {results['live']}</p>"
        if not results['live']:
            content += "<p>Host not reachable.</p></body></html>"
        else:
            content += "<h3>Tested URL</h3>"
            content += f"<p>{results['url']}</p>"

            content += "<h3>Missing Security Headers</h3><ul>"
            for header in results['missing_headers']:
                content += f"<li>{header}</li>"
            content += "</ul>"

            content += "<h3>Sensitive Paths Found</h3><ul>"
            for path in results['sensitive_paths']:
                content += f"<li>{path}</li>"
            content += "</ul>"

            content += "<h3>Admin Panels Found</h3><ul>"
            for admin in results['admin_panels']:
                content += f"<li>{admin}</li>"
            content += "</ul>"

            content += "<h3>CORS Misconfiguration</h3>"
            content += f"<p>{results['cors'] or 'None'}</p>"

            content += "<h3>Open Redirects Found</h3><ul>"
            for ordr in results['open_redirects']:
                content += f"<li>{ordr}</li>"
            content += "</ul>"

            content += "<h3>Potential SQL Injection Vulnerabilities</h3><ul>"
            for sql in results['sql_injection']:
                content += f"<li>{sql}</li>"
            content += "</ul>"

            content += "<h3>Potential XSS Vulnerabilities</h3><ul>"
            for xss in results['xss']:
                content += f"<li>{xss}</li>"
            content += "</ul>"

            content += "<h3>SSL Certificate Info</h3>"
            if results['ssl_cert']:
                content += f"<p>Issuer: {results['ssl_cert'].get('issuer', 'Unknown')}</p>"
                content += f"<p>Expires on: {results['ssl_cert'].get('expiry', 'Unknown')}</p>"
            else:
                content += "<p>SSL info not available or HTTP only.</p>"

        content += "</body></html>"

    else:  # Plain text
        content = f"Bug Bounty Scan Report for {results['target']}\n"
        content += f"Scan Timestamp: {timestamp}\n\n"
        content += f"--- Scan Results for {results['target']} ---\n"
        content += f"Live: {results['live']}\n"
        if not results['live']:
            content += "Host not reachable.\n"
        else:
            content += f"Tested URL: {results['url']}\n"
            content += "Missing Security Headers:\n"
            for header in results['missing_headers']:
                content += f" - {header}\n"

            content += "Sensitive Paths Found:\n"
            for path in results['sensitive_paths']:
                content += f" - {path}\n"

            content += "Admin Panels Found:\n"
            for admin in results['admin_panels']:
                content += f" - {admin}\n"

            content += "CORS Misconfiguration:\n"
            content += f" {results['cors'] or 'None'}\n"

            content += "Open Redirects Found:\n"
            for ordr in results['open_redirects']:
                content += f" - {ordr}\n"

            content += "Potential SQL Injection Vulnerabilities:\n"
            for sql in results['sql_injection']:
                content += f" - {sql}\n"

            content += "Potential XSS Vulnerabilities:\n"
            for xss in results['xss']:
                content += f" - {xss}\n"

            content += "SSL Certificate Info:\n"
            if results['ssl_cert']:
                content += f" Issuer: {results['ssl_cert'].get('issuer', 'Unknown')}\n"
                content += f" Expires on: {results['ssl_cert'].get('expiry', 'Unknown')}\n"
            else:
                content += " SSL info not available or HTTP only.\n"

    # Write report
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Report saved as {filename}")

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Scanner Tool")
    parser.add_argument("target", help="Target URL (e.g. http://example.com)")
    parser.add_argument("--report", choices=["txt", "html"], default="txt", help="Report format (txt or html)")
    args = parser.parse_args()

    url = args.target
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path  # fallback if netloc empty

    print(f"[+] Starting scan on {url}")

    live = is_live(url)
    if not live:
        print(f"[!] Host {url} not reachable.")
        results = {
            "target": domain,
            "url": url,
            "live": False,
            "missing_headers": [],
            "sensitive_paths": [],
            "admin_panels": [],
            "cors": None,
            "open_redirects": [],
            "sql_injection": [],
            "xss": [],
            "ssl_cert": None,
        }
    else:
        print("[*] Checking security headers...")
        missing_headers = check_security_headers(url)

        print("[*] Checking sensitive paths...")
        sensitive_paths = check_sensitive_paths(url)

        print("[*] Checking admin panels...")
        admin_panels = check_admin_panels(url)

        print("[*] Checking CORS misconfiguration...")
        cors = check_cors_misconfig(url)

        print("[*] Checking open redirects...")
        open_redirects = check_open_redirects(url)

        print("[*] Checking SQL Injection vulnerabilities...")
        sql_injection = check_sql_injection(url)

        print("[*] Checking XSS vulnerabilities...")
        xss = check_xss(url)

        print("[*] Checking SSL certificate info...")
        ssl_cert = check_ssl_info(domain) if url.startswith("https") else None

        results = {
            "target": domain,
            "url": url,
            "live": True,
            "missing_headers": missing_headers,
            "sensitive_paths": sensitive_paths,
            "admin_panels": admin_panels,
            "cors": cors,
            "open_redirects": open_redirects,
            "sql_injection": sql_injection,
            "xss": xss,
            "ssl_cert": ssl_cert,
        }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(":", "_").replace("/", "_")
    filename = f"bugbounty_report_{safe_domain}_{timestamp}.{args.report}"
    generate_report(results, filename, args.report)

    print("[+] Scan completed.")

if __name__ == "__main__":
    main()
