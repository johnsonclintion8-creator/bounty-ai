import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "BountyAI-Recon/2.0"}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/config",
    "/swagger.json", "/openapi.json", "/api/v1", "/graphql", "/admin"
]

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Live/Test Key": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Firebase URL": r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
}

def normalize_url(target: str) -> str:
    target = target.strip()
    return target if target.startswith(("http://", "https://")) else "http://" + target

def grade_security_headers(headers: dict) -> dict:
    lower_map = {k.lower(): v for k, v in headers.items()}
    present = [h for h in SECURITY_HEADERS if h.lower() in lower_map]
    missing = [h for h in SECURITY_HEADERS if h.lower() not in lower_map]
    score = len(present)
    grade_map = {6: "A", 5: "B", 4: "C", 3: "D", 2: "E", 1: "F", 0: "F"}
    return {"grade": grade_map[score], "score": f"{score}/{len(SECURITY_HEADERS)}", "present": present, "missing": missing}

def detect_technologies(headers: dict, html_text: str) -> list[str]:
    tech = set()
    h_str = str(headers).lower()
    body = html_text.lower()
    signatures = {
        "Cloudflare": ["cloudflare", "__cf_bm", "cf-ray"],
        "Nginx": ["nginx"],
        "Apache": ["apache"],
        "PHP": ["phpsessid", ".php", "x-powered-by: php"],
        "ASP.NET": ["asp.net", "aspsessionid", "__viewstate"],
        "Express / Node.js": ["x-powered-by: express"],
        "WordPress": ["wp-content", "wp-includes"],
        "React / Next.js": ["__next_data__", "react-root", "_next/static"],
        "Vue.js": ["__vue__", "data-v-"],
        "GraphQL": ["graphql", "__schema"],
    }
    for name, keys in signatures.items():
        if any(k in h_str or k in body for k in keys):
            tech.add(name)
    return sorted(tech)

def scan_secrets(text: str) -> list[dict]:
    hits = []
    for label, pat in SECRET_PATTERNS.items():
        for match in set(re.findall(pat, text)):
            masked = match[:6] + "..." + match[-4:] if len(match) > 12 else "***"
            hits.append({"type": label, "preview": masked})
    return hits

def extract_js_endpoints(js_text: str) -> list[str]:
    patterns = [
        r'["\'](\/[a-zA-Z0-9_\-\/\.]+(?:\?[a-zA-Z0-9_\-=&]+)?)["\']',
        r'["\'](https?:\/\/[^"\'\s]+)["\']',
    ]
    found = set()
    for pat in patterns:
        for match in re.findall(pat, js_text):
            if not match.endswith((".png", ".jpg", ".jpeg", ".gif", ".css", ".svg", ".woff", ".woff2")):
                found.add(match)
    return sorted(found)

def is_in_scope(candidate_url: str, base_host: str, allow_subdomains: bool = False) -> bool:
    cand_host = urlparse(candidate_url).netloc.lower()
    base_host = base_host.lower()
    if not cand_host:
        return False
    if cand_host == base_host:
        return True
    return allow_subdomains and cand_host.endswith("." + base_host.split(":")[0])

def get_subdomains(target_url: str) -> list[str]:
    host = urlparse(target_url).netloc.split(":")[0]
    try:
        r = requests.get(f"https://crt.sh.{host}&output=json", timeout=15)
        if r.status_code == 200:
            return sorted({x["name_value"].lstrip("*.") for x in r.json() if "name_value" in x})
    except Exception:
        pass
    return []


def enrich_passive_osint_and_schemas(base_url: str, js_files: list) -> dict:
    import socket
    from urllib.parse import urlparse, quote_plus, parse_qs
    parsed = urlparse(base_url)
    host = parsed.netloc.split(":")[0]
    origin = f"{parsed.scheme}://{parsed.netloc}"
    out = {
        "shodan_internetdb": {},
        "wayback_urls": [],
        "wayback_params": [],
        "exposed_api_schemas": [],
        "exposed_sourcemaps": [],
        "dork_links": {
            "github_secrets": f"https://github.com{quote_plus(host)}%22+%28api_key+OR+secret+OR+token+OR+password%29&type=code",
            "github_endpoints": f"https://github.com{quote_plus(host)}%22+%28%22%2Fapi%2F%22+OR+%22graphql%22+OR+%22internal%22%29&type=code",
            "google_subdomains": f"https://google.com*.{quote_plus(host)}",
            "google_files": f"https://google.com{quote_plus(host)}+ext%3Aenv+OR+ext%3Alog+OR+ext%3Abak+OR+ext%3Asql+OR+ext%3Ajson",
        },
    }
    try:
        ip = socket.gethostbyname(host)
        r = requests.get(f"https://shodan.io{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            out["shodan_internetdb"] = {
                "ip": ip,
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", [])[:15],
                "cpes": data.get("cpes", [])[:10],
                "tags": data.get("tags", []),
            }
    except Exception:
        pass

    try:
        wb = requests.get(
            f"https://archive.org*.{host}/*&output=json&fl=original&collapse=urlkey&limit=40",
            timeout=6,
        )
        if wb.status_code == 200:
            rows = wb.json()[1:]
            urls, params = [], set()
            for row in rows:
                u = row[0]
                urls.append(u)
                for k in parse_qs(urlparse(u).query).keys():
                    params.add(k)
            out["wayback_urls"] = urls[:25]
            out["wayback_params"] = sorted(params)[:25]
    except Exception:
        pass

    for schema_path in ("/swagger.json", "/openapi.json", "/v2/api-docs", "/api-docs"):
        try:
            sr = requests.get(origin + schema_path, headers=HEADERS, timeout=4, allow_redirects=False)
            if sr.status_code == 200 and any(k in sr.text[:400].lower() for k in ("openapi", "swagger", "paths")):
                out["exposed_api_schemas"].append(origin + schema_path)
        except Exception:
            pass

    for js_u in js_files[:8]:
        map_url = js_u.split("?")[0] + ".map"
        try:
            mr = requests.head(map_url, headers=HEADERS, timeout=3, allow_redirects=False)
            if mr.status_code == 200:
                out["exposed_sourcemaps"].append(map_url)
        except Exception:
            pass

    return out

def run_recon(target: str, ctf_mode: bool = False, max_pages: int = 15, allow_subdomains: bool = False) -> dict:
    url = normalize_url(target)
    parsed_root = urlparse(url)
    base_host = parsed_root.netloc
    root_origin = f"{parsed_root.scheme}://{base_host}"

    results = {
        "target": url,
        "mode": "CTF / Single-Target" if ctf_mode else "Full Bug Bounty",
        "status_code": None,
        "technologies": [],
        "security_grade": {},
        "exposed_paths": [],
        "leaked_secrets": [],
        "headers": {},
        "subdomains": [],
        "crawled_pages": [],
        "query_params": {},
        "forms": [],
        "js_files": [],
        "js_endpoints": [],
        "errors": [],
    }

    if not ctf_mode:
        results["subdomains"] = get_subdomains(url)[:100]

    visited, to_visit = set(), [url]
    all_scripts, all_js_endpoints, all_secrets = set(), set(), []

    try:
        while to_visit and len(visited) < max_pages:
            curr = to_visit.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            r = requests.get(curr, headers=HEADERS, timeout=10)
            if len(visited) == 1:
                results["status_code"] = r.status_code
                results["headers"] = dict(r.headers)
                results["security_grade"] = grade_security_headers(results["headers"])
                results["technologies"] = detect_technologies(results["headers"], r.text)

            all_secrets.extend(scan_secrets(r.text))
            qs = parse_qs(urlparse(curr).query)
            if qs:
                results["query_params"][curr] = list(qs.keys())

            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                full_link = urljoin(curr, a["href"]).split("#")[0]
                if is_in_scope(full_link, base_host, allow_subdomains) and full_link not in visited and full_link not in to_visit:
                    to_visit.append(full_link)

            for f in soup.find_all("form"):
                action = urljoin(curr, f.get("action") or "")
                inps = [{"name": x.get("name") or x.get("id") or "unnamed", "type": x.get("type", x.name)} for x in f.find_all(["input", "textarea", "select"])]
                results["forms"].append({"page": curr, "method": f.get("method", "GET").upper(), "action": action, "inputs": inps})

            for s in soup.find_all("script"):
                if s.get("src"):
                    all_scripts.add(urljoin(curr, s.get("src")))
                elif s.string:
                    all_js_endpoints.update(extract_js_endpoints(s.string))
                    all_secrets.extend(scan_secrets(s.string))

        for js_url in sorted(all_scripts)[:10]:
            try:
                jr = requests.get(js_url, headers=HEADERS, timeout=8)
                if jr.status_code == 200:
                    all_js_endpoints.update(extract_js_endpoints(jr.text))
                    all_secrets.extend(scan_secrets(jr.text))
            except Exception:
                pass

        for path in SENSITIVE_PATHS:
            try:
                pr = requests.get(root_origin + path, headers=HEADERS, timeout=5, allow_redirects=False)
                if pr.status_code in (200, 401, 403):
                    results["exposed_paths"].append({"path": path, "status": pr.status_code})
            except Exception:
                pass
    except Exception as e:
        results["errors"].append(str(e))

    results["crawled_pages"] = sorted(visited)
    results["js_files"] = sorted(all_scripts)[:30]
    results["js_endpoints"] = sorted(all_js_endpoints)[:50]
    seen_sec = set()
    for sec in all_secrets:
        key = (sec["type"], sec["preview"])
        if key not in seen_sec:
            seen_sec.add(key)
            results["leaked_secrets"].append(sec)
    results["passive_osint"] = enrich_passive_osint_and_schemas(url, results.get("js_files", []))
    return results
