import os
import json
import datetime
from google import genai

MODELS = ["gemini-3.8-flash", "gemini-3.5-flash-lite"]

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
    for model_name in MODELS:
        try:
            resp = client.models.generate_content(model=model_name, contents=prompt)
            if resp and resp.text:
                return resp.text
        except Exception as e:
            last_err = e
    raise RuntimeError(f"All Gemini models busy or unavailable. Last error: {last_err}")

def save_report(target: str, markdown_body: str) -> str:
    os.makedirs("reports", exist_ok=True)
    safe_name = "".join(c if c.isalnum() else "_" for c in target)[:40].strip("_") or "target"
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("reports", f"{safe_name}_{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown_body)
    return path
