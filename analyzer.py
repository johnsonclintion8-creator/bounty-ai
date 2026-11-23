import os
import json
import time
import datetime
from google import genai

FALLBACK_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
    "gemini-flash-latest",
]

def _discover_models(client) -> list[str]:
    discovered = []
    try:
        for m in client.models.list():
            name = getattr(m, "name", "").replace("models/", "")
            methods = getattr(m, "supported_generation_methods", []) or []
            if "flash" in name.lower() and "image" not in name.lower() and "audio" not in name.lower() and "tts" not in name.lower():
                if not methods or "generateContent" in methods:
                    discovered.append(name)
    except Exception:
        pass
    ordered = []
    for candidate in discovered + FALLBACK_MODELS:
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    return ordered[:6]

def analyze_recon(recon_data: dict, api_key: str = "") -> str:
    key = (api_key or os.environ.get("GEMINI_API_KEY", "")).strip()
    if not key:
        raise ValueError("Missing GEMINI_API_KEY. Add it in Streamlit Secrets or the sidebar.")
    client = genai.Client(api_key=key)
    prompt = f"""You are an expert bug bounty triage assistant. Analyze this reconnaissance JSON for an authorized target and produce a clear, actionable security report in Markdown.

Include:
1. **Executive Summary & Attack Surface Score**
2. **Detected Tech Stack & Missing Security Headers**
3. **High-Priority Manual Test Vectors** (specific URLs, forms, parameters, or JS endpoints to test for SQLi, XSS, IDOR, Auth Bypass, or Info Disclosure—never execute attacks, only provide safe manual verification steps)
4. **Remediation Recommendations**

Recon Data:
{json.dumps(recon_data, indent=2)[:28000]}
"""
    last_err = None
    models = _discover_models(client)
    for attempt in range(3):
        for model_name in models:
            try:
                resp = client.models.generate_content(model=model_name, contents=prompt)
                if resp and resp.text:
                    return resp.text
            except Exception as e:
                last_err = e
                err_str = str(e)
                if "404" in err_str or "NOT_FOUND" in err_str:
                    continue
        if attempt < 2:
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"AI service temporarily busy after 3 retries ({last_err}). Your scan quota was NOT charged—please click Run again in a few seconds.")

def save_report(target: str, markdown_body: str) -> str:
    os.makedirs("reports", exist_ok=True)
    safe_name = "".join(c if c.isalnum() else "_" for c in target)[:40].strip("_") or "target"
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("reports", f"{safe_name}_{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown_body)
    return path
