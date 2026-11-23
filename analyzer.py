import os
import json
import time
import datetime
from google import genai
from google.genai import types

SYSTEM_PROMPT = """You are an expert application security researcher assisting with authorized bug bounty and CTF reconnaissance.
Analyze the structured reconnaissance JSON data (HTTP headers, subdomains, crawled internal links, URL query parameters, HTML forms, JavaScript files, extracted JS endpoints, and robots.txt).
Provide a clean, actionable Markdown report organized into:
1. Executive Attack Surface Summary
2. High-Value Paths, Subdomains & JS Endpoints
3. Detected Technologies & Missing Security Headers
4. Priority Input Vectors (Forms & Query Parameters for SQLi, XSS, IDOR, Auth Bypass)
5. Step-by-Step Manual Testing Plan"""

FALLBACK_MODELS = ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash"]

def analyze_recon(recon_data: dict, api_key: str | None = None) -> str:
    key = (api_key or "").strip() or os.environ.get("GEMINI_API_KEY")
    client = genai.Client(api_key=key) if key else genai.Client()
    payload = json.dumps(recon_data, indent=2)
    last_err = None

    for model_name in FALLBACK_MODELS:
        try:
            res = client.models.generate_content(
                model=model_name,
                contents=f"Analyze this authorized reconnaissance output:\n\n{payload}",
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=0.2,
                ),
            )
            return f"*Generated using `{model_name}`*\n\n" + res.text
        except Exception as e:
            last_err = e
            if "503" in str(e) or "429" in str(e) or "404" in str(e):
                time.sleep(1)
                continue
            raise
    raise RuntimeError(f"All Gemini models busy or unavailable. Last error: {last_err}")

def save_report(target: str, markdown_text: str) -> str:
    os.makedirs("reports", exist_ok=True)
    clean = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
        .strip("_")
    )
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("reports", f"{clean}_{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown_text)
    return path
