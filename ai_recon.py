import os, sys, datetime, requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from google import genai
from google.genai import types

client = genai.Client()

PROMPT = "You are an expert application security researcher assisting with authorized bug bounty and CTF reconnaissance. Analyze the provided subdomain list, HTTP headers, robots.txt, discovered internal links, HTML forms, and linked JavaScript files. Provide a structured Markdown report covering: 1. Top High-Value Subdomains or Paths, 2. Detected Technologies & Security Headers, 3. High-Value HTML Forms & Parameters, 4. Interesting JavaScript Files & Manual Testing Priorities."

def get_subs(domain):
    clean = domain.replace("https://", "").replace("http://", "").split("/").pop(0).split(":")[0]
    try:
        r = requests.get("https://crt.sh." + clean + "&output=json", timeout=15)
        if r.status_code == 200:
            return sorted({x["name_value"].lstrip("*.") for x in r.json() if "name_value" in x})
    except Exception:
        pass
    return []

def get_action(f):
    a = f.get("action")
    return str(a) if a else "N/A"

def gather(url, ctf_mode=False):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    out = ["Target: " + url, "Mode: " + ("CTF / Single-Target" if ctf_mode else "Full Bug Bounty")]
    hdrs = {"User-Agent": "BugBountyReconAssistant/1.0"}
    if not ctf_mode:
        print("[*] Querying crt.sh for subdomains...")
        subs = get_subs(url)
        out.append("Subdomains (" + str(len(subs)) + " results):")
        out.extend("  " + s for s in subs[:100])
    print("[*] Fetching headers, crawling internal links, forms, and JS...")
    base_host = urlparse(url).netloc
    visited, to_visit = set(), [url]
    all_forms, all_scripts = [], set()
    try:
        while to_visit and len(visited) < 15:
            curr = to_visit.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            r = requests.get(curr, headers=hdrs, timeout=10)
            if len(visited) == 1:
                out.append("Status: " + str(r.status_code))
                out.extend("  " + k + ": " + v for k, v in r.headers.items())
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                full_link = urljoin(curr, a["href"]).split("#")[0]
                if urlparse(full_link).netloc == base_host and full_link not in visited and full_link not in to_visit:
                    to_visit.append(full_link)
            for f in soup.find_all("form"):
                inps = [x.get("name") or x.get("id") or "unnamed" for x in f.find_all(["input", "textarea", "select"])]
                all_forms.append("Page=" + curr + " | method=" + f.get("method", "GET").upper() + " action=" + get_action(f) + " inputs=" + str(inps))
            for s in soup.find_all("script"):
                if s.get("src"):
                    all_scripts.add(urljoin(curr, s.get("src")))
        out.append("Crawled Internal Pages (" + str(len(visited)) + "):")
        out.extend("  " + p for p in sorted(visited))
        out.append("HTML Forms (" + str(len(all_forms)) + "):")
        out.extend("  " + fm for fm in all_forms[:25])
        out.append("External JS Files (" + str(len(all_scripts)) + "):")
        out.extend("  " + sc for sc in sorted(all_scripts)[:25])
    except Exception as e:
        out.append("Web fetch error: " + str(e))
    try:
        parsed = urlparse(url)
        robots_url = parsed.scheme + "://" + parsed.netloc + "/robots.txt"
        rb = requests.get(robots_url, headers=hdrs, timeout=10)
        if rb.status_code == 200:
            out.append("robots.txt:\n" + rb.text[:1500])
    except Exception:
        pass
    return "\n".join(out)

def save_rep(target, text):
    os.makedirs("reports", exist_ok=True)
    clean = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_").strip("_")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("reports", clean + "_" + ts + ".md")
    open(path, "w", encoding="utf-8").write(text)
    return path

if __name__ == "__main__":
    ctf = "--ctf" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--ctf"]
    target = args[0]
    data = gather(target, ctf_mode=ctf)
    print("[*] Analyzing with Gemini 2.5 Flash...")
    res = client.models.generate_content(model="gemini-3.8-flash", contents="Analyze this recon data:\n\n" + data, config=types.GenerateContentConfig(system_instruction=PROMPT, temperature=0.2))
    print(res.text)
    print("[+] Saved report to: " + save_rep(target, res.text))
