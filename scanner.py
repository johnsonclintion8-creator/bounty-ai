import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "BountyAI-Recon/1.0"}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        return "http://" + target
    return target

def grade_security_headers(headers: dict) -> dict:
    lower_map = {k.lower(): v for k, v in headers.items()}
    present = []
    missing = []
    for h in SECURITY_HEADERS:
        if h.lower() in lower_map:
            present.append(h)
        else:
            missing.append(h)
    score = len(present)
    grade_map = {6: "A", 5: "B", 4: "C", 3: "D", 2: "E", 1: "F", 0: "F"}
    return {
        "grade": grade_map[score],
        "score": f"{score}/{len(SECURITY_HEADERS)}",
        "present": present,
        "missing": missing,
    }

def is_in_scope(candidate_url: str, base_host: str, allow_subdomains: bool = False) -> bool:
    cand_host = urlparse(candidate_url).netloc.lower()
    base_host = base_host.lower()
    if not cand_host:
        return False
    if cand_host == base_host:
        return True
    if allow_subdomains and cand_host.endswith("." + base_host.split(":")):
        return True
    return False

def get_subdomains(target_url: str) -> list[str]:
    host = urlparse(target_url).netloc.split(":")
    try:
        r = requests.get(f"https://crt.sh.{host}&output=json", timeout=15)
        if r.status_code == 200:
            return sorted({x["name_value"].lstrip("*.") for x in r.json() if "name_value" in x})
    except Exception:
        pass
    return []

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

def run_recon(target: str, ctf_mode: bool = False, max_pages: int = 15, allow_subdomains: bool = False) -> dict:
    url = normalize_url(target)
    parsed_root = urlparse(url)
    base_host = parsed_root.netloc

    results = {
        "target": url,
        "mode": "CTF / Single-Target" if ctf_mode else "Full Bug Bounty",
        "status_code": None,
        "security_grade": {},
        "headers": {},
        "subdomains": [],
        "crawled_pages": [],
        "query_params": {},
        "forms": [],
        "js_files": [],
        "js_endpoints": [],
        "robots_txt": "",
        "errors": [],
    }

    if not ctf_mode:
        results["subdomains"] = get_subdomains(url)[:100]

    visited = set()
    to_visit = [url]
    all_scripts = set()
    all_js_endpoints = set()

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

            qs = parse_qs(urlparse(curr).query)
            if qs:
                results["query_params"][curr] = list(qs.keys())

            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                full_link = urljoin(curr, a["href"]).split("#")
                if is_in_scope(full_link, base_host, allow_subdomains) and full_link not in visited and full_link not in to_visit:
                    to_visit.append(full_link)

            for f in soup.find_all("form"):
                action = urljoin(curr, f.get("action") or "")
                inps = [
                    {
                        "name": x.get("name") or x.get("id") or "unnamed",
                        "type": x.get("type", x.name),
                    }
                    for x in f.find_all(["input", "textarea", "select"])
                ]
                results["forms"].append({
                    "page": curr,
                    "method": f.get("method", "GET").upper(),
                    "action": action,
                    "inputs": inps,
                })

            for s in soup.find_all("script"):
                if s.get("src"):
                    all_scripts.add(urljoin(curr, s.get("src")))
                elif s.string:
                    all_js_endpoints.update(extract_js_endpoints(s.string))

        for js_url in sorted(all_scripts)[:10]:
            try:
                jr = requests.get(js_url, headers=HEADERS, timeout=8)
                if jr.status_code == 200:
                    all_js_endpoints.update(extract_js_endpoints(jr.text))
            except Exception:
                pass

    except Exception as e:
        results["errors"].append(str(e))

    results["crawled_pages"] = sorted(visited)
    results["js_files"] = sorted(all_scripts)[:30]
    results["js_endpoints"] = sorted(all_js_endpoints)[:50]

    try:
        robots_url = f"{parsed_root.scheme}://{base_host}/robots.txt"
        rb = requests.get(robots_url, headers=HEADERS, timeout=8)
        if rb.status_code == 200:
            results["robots_txt"] = rb.text[:2000]
    except Exception:
        pass

    return results
