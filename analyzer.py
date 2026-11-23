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

def analyze_recon(recon_data: dict, api_key: str = "", program_policy: str = "", scan_diff: dict | None = None) -> str:
    import json
    key = (api_key or os.environ.get("GEMINI_API_KEY", "")).strip()
    if not key:
        raise ValueError("Missing GEMINI_API_KEY.")
    client = genai.Client(api_key=key)
    policy_instruction = ""
    if program_policy and program_policy.strip():
        policy_instruction = (
            "IMPORTANT - PROGRAM SCOPE & RULES-OF-ENGAGEMENT GATEKEEPER:\n"
            "Evaluate every discovered subdomain, endpoint, and finding against these program rules:\n"
            + program_policy.strip()[:6000]
            + "\n\nBegin the report with '## 0. Program Scope & Eligibility Gatekeeper' tagging each item as "
            "[IN-SCOPE / ELIGIBLE], [OUT-OF-SCOPE - DO NOT TEST], or [EXCLUDED / N/A RISK]. "
            "If missing security headers or cookie flags are excluded, mark them [EXCLUDED / N/A RISK] and omit them from High-Priority Manual Test Vectors.\n\n"
        )

    diff_instruction = ""
    if scan_diff and scan_diff.get("has_previous"):
        diff_instruction = (
            "ATTACK SURFACE DRIFT DETECTED (Compare against prior scan of this target):\n"
            + json.dumps(scan_diff, indent=2)
            + "\nInclude a concise 'What Changed Since Last Scan' callout highlighting newly added JS files, endpoints, or open ports.\n\n"
        )
    prompt = (
        policy_instruction
        + diff_instruction
        + "You are an expert application security researcher performing non-destructive bug bounty triage.\n"
        + "Analyze the following reconnaissance data and produce a concise, structured markdown triage report with:\n"
        + "1. Executive Summary & Tech Stack\n"
        + "2. High-Priority Manual Test Vectors (with safe, non-destructive verification steps)\n"
        + "3. Security Header & Configuration Remediation\n\n"
        + "Recon Data:\n"
        + json.dumps(recon_data, indent=2)[:28000]
    )
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
