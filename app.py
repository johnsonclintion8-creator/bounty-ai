import re
import os, html
import streamlit as st
from fpdf import FPDF
from scanner import run_recon, extract_js_endpoints
from analyzer import analyze_recon, save_report
from database import (
    init_db, register_user, authenticate_user, reset_user_password,
    can_user_scan, increment_user_quota, upgrade_user_to_pro,
    get_user_status, save_cloud_report, get_user_reports, FREE_MONTHLY_LIMIT
)
from billing import create_checkout_session, verify_checkout_session, ADMIN_PROMO_CODE

init_db()
st.set_page_config(page_title="BountyAI Recon SaaS", page_icon="🛡️", layout="wide")

def build_html_report(target: str, markdown_body: str, grade_info: dict) -> str:
    escaped = html.escape(markdown_body)
    grade, score = grade_info.get("grade", "N/A"), grade_info.get("score", "N/A")
    missing = ", ".join(grade_info.get("missing", [])) or "None"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>BountyAI Report - {html.escape(target)}</title>
<style>body {{ font-family: sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }} .header {{ background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 10px; }} .badge {{ background: #ef4444; color: white; padding: 4px 12px; border-radius: 6px; }} pre {{ white-space: pre-wrap; background: #f8fafc; padding: 20px; border-radius: 8px; }}</style>
</head><body><div class="header"><h1>🛡️ BountyAI Security Report</h1><p><strong>Target:</strong> {html.escape(target)} | <span class="badge">Grade: {grade} ({score})</span></p><p><strong>Missing:</strong> {html.escape(missing)}</p></div><pre>{escaped}</pre></body></html>"""

def parse_burp_xml(raw_xml: str) -> dict:
    import base64
    from urllib.parse import urlparse, parse_qs
    from xml.parsers import expat

    items, curr, tag, buf = [], {}, "", []

    def start_el(name, attrs):
        nonlocal curr, tag, buf
        tag = name
        buf = []
        if name == "item":
            curr = {"is_b64": False}
        elif name in ("request", "response") and attrs.get("base64") == "true":
            curr["is_b64"] = True

    def char_data(data):
        buf.append(data)

    def end_el(name):
        nonlocal curr, tag, buf
        val = "".join(buf).strip()
        if name in ("url", "method", "status", "path"):
            curr[name] = val
        elif name == "request":
            if curr.get("is_b64") and val:
                try:
                    val = base64.b64decode(val).decode("utf-8", errors="ignore")
                except Exception:
                    val = ""
            curr["req_body"] = val.split("\r\n\r\n", 1)[-1][:500]
            curr["is_b64"] = False
        elif name == "item" and curr.get("url"):
            items.append(curr)
            curr = {}
        tag = ""
        buf = []

    parser = expat.ParserCreate()
    parser.StartElementHandler = start_el
    parser.CharacterDataHandler = char_data
    parser.EndElementHandler = end_el
    parser.Parse(raw_xml.encode("utf-8", errors="ignore"), True)

    seen, endpoints = set(), []
    for it in items:
        u = urlparse(it.get("url", ""))
        key = (it.get("method", "GET"), u.netloc, u.path)
        if key in seen:
            continue
        seen.add(key)
        params = list(parse_qs(u.query).keys())
        body = it.get("req_body", "")
        if "=" in body and not body.lstrip().startswith("<"):
            params += [kv.split("=")[0] for kv in body.split("&") if "=" in kv][:15]
        endpoints.append({
            "method": it.get("method", "GET"),
            "url": f"{u.scheme}://{u.netloc}{u.path}",
            "status": it.get("status", ""),
            "params": list(dict.fromkeys(params))[:20],
        })
    return {"total_items": len(items), "unique_endpoints": endpoints[:100]}

def build_burp_scope(target: str, recon_data: dict) -> str:
    import json
    from urllib.parse import urlparse
    parsed = urlparse(target if "://" in target else "https://" + target)
    host = parsed.netloc.split(":")[0] or target
    hosts = [host] + [s for s in recon_data.get("subdomains", []) if s and s != host]
    include_rules = [
        {"enabled": True, "file": "^/.*", "host": rf"^{re.escape(h)}$", "port": "", "protocol": "any"}
        for h in hosts[:100]
    ]
    exclude_rules = [
        {"enabled": True, "file": r".*\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$", "host": ".*", "port": "", "protocol": "any"}
    ]
    return json.dumps({"target": {"scope": {"advanced_mode": True, "include": include_rules, "exclude": exclude_rules}}}, indent=2)

def build_pdf_report(target: str, markdown_body: str, grade_info: dict) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    w = pdf.epw
    pdf.set_font("Helvetica", "B", 15)
    pdf.multi_cell(w, 9, f"BountyAI Security Report: {target[:60]}", new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(w, 7, f"Header Grade: {grade_info.get('grade', 'N/A')} ({grade_info.get('score', '0/6')})", new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
    pdf.ln(3)
    in_code = False
    for raw_line in markdown_body.splitlines():
        pdf.set_x(pdf.l_margin)
        line = raw_line.encode("latin-1", "replace").decode("latin-1").strip()
        if line.startswith("```"):
            in_code = not in_code
            pdf.ln(1)
            continue
        if in_code:
            pdf.set_font("Courier", "", 8.5)
            pdf.multi_cell(w, 5, "  " + line, new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
            continue
        if not line or line == "---":
            pdf.ln(2)
            continue
        clean = re.sub(r"\*\*(.*?)\*\*", lambda m: m.group(1), line).replace("`", "")
        if clean.startswith("### "):
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 11)
            pdf.multi_cell(w, 6, clean[4:], new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
        elif clean.startswith("## "):
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 12)
            pdf.multi_cell(w, 7, clean[3:], new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
        elif clean.startswith("# "):
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 14)
            pdf.multi_cell(w, 8, clean[2:], new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
        elif clean.startswith(("* ", "- ")):
            pdf.set_font("Helvetica", "", 9.5)
            pdf.multi_cell(w, 5.5, "  - " + clean[2:], new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
        else:
            pdf.set_font("Helvetica", "", 9.5)
            pdf.multi_cell(w, 5.5, clean, new_x="LMARGIN", new_y="NEXT", wrapmode="CHAR")
    return bytes(pdf.output())

params = st.query_params
if "session_id" in params:
    ok, paid_uid, msg = verify_checkout_session(params["session_id"])
    if ok and paid_uid:
        upgrade_user_to_pro(paid_uid)
        st.success(msg)
    else:
        st.warning(msg)
    st.query_params.clear()

if "user" not in st.session_state:
    st.title("🛡️ BountyAI — Authorized Recon & AI Triage")
    st.caption("Attack surface mapping, tech fingerprinting, secret detection & AI vulnerability triage.")
    tab_login, tab_signup, tab_reset = st.tabs(["🔑 Sign In", "✨ Create Account", "🔄 Reset Password"])
    with tab_login:
        with st.form("login_form"):
            login_email = st.text_input("Email")
            login_pw = st.text_input("Password", type="password")
            if st.form_submit_button("Sign In", type="primary", use_container_width=True):
                user = authenticate_user(login_email, login_pw)
                if user:
                    st.session_state["user"] = user
                    st.rerun()
                else:
                    st.error("Invalid email or password.")
    with tab_signup:
        with st.form("signup_form"):
            reg_email = st.text_input("Email")
            reg_pw = st.text_input("Password (min 6 characters)", type="password")
            agree_tos = st.checkbox("I agree to scan only targets where I have explicit written authorization or CTF scope.")
            if st.form_submit_button("Create Free Account", type="primary", use_container_width=True):
                if not agree_tos:
                    st.error("You must accept the Authorized Scope Terms to create an account.")
                else:
                    ok, msg = register_user(reg_email, reg_pw)
                    st.success(msg + " Switch to Sign In.") if ok else st.error(msg)
    with tab_reset:
        with st.form("reset_form"):
            rst_email = st.text_input("Account Email")
            rst_pw = st.text_input("New Password (min 6 characters)", type="password")
            if st.form_submit_button("Update Password", use_container_width=True):
                ok, msg = reset_user_password(rst_email, rst_pw)
                st.success(msg) if ok else st.error(msg)
    st.stop()
uid = st.session_state["user"]["id"]
user_info = get_user_status(uid)
tier, used = user_info["tier"], user_info["scans_used"]

with st.sidebar:
    st.subheader(f"👤 {user_info['email']}")
    if tier == "free":
        remaining = max(0, FREE_MONTHLY_LIMIT - used)
        st.info(f"**Plan:** FREE ({remaining}/{FREE_MONTHLY_LIMIT} scans left this month)")
        with st.expander("🚀 Upgrade to Pro ($29.99/mo)", expanded=True):
            if st.button("Checkout with Stripe", type="primary", use_container_width=True):
                ok, res_url = create_checkout_session(user_info["email"], uid)
                st.markdown(f"[👉 Complete Payment on Stripe]({res_url})") if ok else st.warning(res_url)
            if ADMIN_PROMO_CODE:
                promo = st.text_input("Promo Code", placeholder="Enter code")
                if st.button("Redeem Code", use_container_width=True):
                    if promo.strip() == ADMIN_PROMO_CODE:
                        upgrade_user_to_pro(uid)
                        st.success("Upgraded to PRO!")
                        st.rerun()
                    else:
                        st.error("Invalid promo code.")
    else:
        st.success("**Plan:** PRO (Unlimited Scans)")
    if st.button("Log Out", use_container_width=True):
        del st.session_state["user"]
        st.rerun()
    st.divider()
    st.header("Scan Settings")
    ctf_mode = st.toggle("CTF / Single-Target Mode (Skip crt.sh)", value=True)
    allow_subs = st.toggle("Crawl Subdomains in Scope", value=False)
    max_pages = st.slider("Max Internal Pages to Crawl", 1, 30, 10)
    st.divider()
    user_api_key = st.text_input("Optional Gemini API Key", type="password")

st.title("🛡️ BountyAI — Recon & Vulnerability Triage")
tab_live, tab_files, tab_history = st.tabs(["🌐 Live Target Scan", "📂 Upload JS / Logs", "📄 Saved Reports"])

with tab_live:
    target_url = st.text_input("Target URL (Authorized Scope Only)", placeholder="https://example.com")
    with st.expander("Program Scope & Rules-of-Engagement (Optional ? Filters Out-of-Scope & N/A Noise)"):
        program_policy = st.text_area(
            "Paste HackerOne / Bugcrowd In-Scope Assets & Exclusions",
            placeholder="Example:\nIn Scope: *.example.com, ://example.com\nOut of Scope: ://example.com, missing HTTP security headers, self-XSS, rate limiting",
            height=110,
        )
    if st.button("Run Recon & AI Triage", type="primary", use_container_width=True):
        if not target_url.strip():
            st.warning("Enter a target URL first.")
        else:
            allowed, quota_msg = can_user_scan(uid)
            if not allowed:
                st.error(quota_msg)
            else:
                with st.spinner("Fingerprinting stack, probing paths, scanning JS secrets & crawling..."):
                    recon_data = run_recon(target_url, ctf_mode=ctf_mode, max_pages=max_pages, allow_subdomains=allow_subs)
                if not recon_data.get("status_code"):
                    st.error(f"Target unreachable or blocked request ({', '.join(recon_data.get('errors', ['No response']))}). Your scan quota was NOT charged.")
                else:
                    g = recon_data.get("security_grade", {})
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Header Grade", f"{g.get('grade', '?')} ({g.get('score', '0/6')})")
                    c2.metric("Pages Crawled", len(recon_data["crawled_pages"]))
                    c3.metric("Forms & Params", len(recon_data["forms"]) + len(recon_data["query_params"]))
                    c4.metric("Exposed Paths / Secrets", len(recon_data["exposed_paths"]) + len(recon_data["leaked_secrets"]))
                    if recon_data.get("technologies"):
                        st.info("**Detected Stack:** " + ", ".join(recon_data["technologies"]))
                    if recon_data.get("leaked_secrets"):
                        st.error(f"**Potential Secrets Detected in Source/JS:** {recon_data['leaked_secrets']}")
                    with st.spinner("Generating AI vulnerability triage report..."):
                        try:
                            report_md = analyze_recon(recon_data, api_key=user_api_key, program_policy=program_policy)
                            increment_user_quota(uid)
                            save_cloud_report(uid, target_url, f"{g.get('grade', '?')} ({g.get('score', '0/6')})", report_md)
                            saved_path = save_report(target_url, report_md)
                            st.session_state["last_report"], st.session_state["last_raw"] = report_md, recon_data
                            st.session_state["last_path"], st.session_state["last_target"] = saved_path, target_url
                        except Exception as e:
                            st.error(f"AI Analysis Error (Quota NOT charged): {e}")

    if "last_report" in st.session_state:
        base_name = os.path.basename(st.session_state["last_path"]).replace(".md", "")
        grade_data = st.session_state["last_raw"].get("security_grade", {})
        html_export = build_html_report(st.session_state.get("last_target", "target"), st.session_state["last_report"], grade_data)
        pdf_export = build_pdf_report(st.session_state.get("last_target", "target"), st.session_state["last_report"], grade_data)
        burp_export = build_burp_scope(st.session_state.get("last_target", "target"), st.session_state["last_raw"])
        d1, d2, d3, d4 = st.columns(4)
        d1.download_button("Download Markdown (.md)", st.session_state["last_report"], f"{base_name}.md", "text/markdown", use_container_width=True)
        d2.download_button("Download Branded HTML (.html)", html_export, f"{base_name}.html", "text/html", use_container_width=True)
        d3.download_button("Download Client PDF (.pdf)", pdf_export, f"{base_name}.pdf", "application/pdf", use_container_width=True)
        d4.download_button("⬇ Burp Scope (.json)", burp_export, f"{base_name}_burp_scope.json", "application/json", use_container_width=True)
        st.markdown(st.session_state["last_report"])
        with st.expander("View Raw Recon JSON"):
            st.json(st.session_state["last_raw"])

with tab_files:
    uploaded = st.file_uploader("Drop a Burp Suite .xml export, or a .js, .txt, .json, .log file", type=["xml", "js", "txt", "json", "log"])
    if uploaded is not None:
        raw_text = uploaded.read().decode("utf-8", errors="ignore")
        is_burp_xml = uploaded.name.lower().endswith(".xml")
        burp_summary = parse_burp_xml(raw_text) if is_burp_xml else None
        endpoints = [e["url"] for e in burp_summary["unique_endpoints"]] if burp_summary else (extract_js_endpoints(raw_text) if uploaded.name.endswith(".js") else [])
        st.write(f"**File:** `{uploaded.name}` | **Extracted Endpoints/Paths:** {len(endpoints)}")
        if st.button("Analyze Uploaded File with AI"):
            allowed, quota_msg = can_user_scan(uid)
            if not allowed:
                st.error(quota_msg)
            else:
                with st.spinner("Analyzing file..."):
                    try:
                        payload = {"file": uploaded.name, "burp_http_history": burp_summary} if burp_summary else {"file": uploaded.name, "paths": endpoints, "preview": raw_text[:15000]}
                        file_rep = analyze_recon(payload, api_key=user_api_key, program_policy=program_policy)
                        increment_user_quota(uid)
                        save_cloud_report(uid, f"File: {uploaded.name}", "File Audit", file_rep)
                        st.markdown(file_rep)
                    except Exception as e:
                        st.error(f"AI Analysis Error (Quota NOT charged): {e}")

with tab_history:
    cloud_reps = get_user_reports(uid)
    if cloud_reps:
        labels = [f"{r['created_at']} — {r['target']} (Grade: {r['grade']})" for r in cloud_reps]
        choice = st.selectbox("Select a saved cloud report", range(len(labels)), format_func=lambda i: labels[i])
        chosen = cloud_reps[choice]
        st.download_button("⬇️ Download Markdown (.md)", chosen["markdown_body"], f"bountyai_report_{chosen['id']}.md", "text/markdown")
        st.markdown(chosen["markdown_body"])
    else:
        st.info("No saved cloud reports yet. Run a scan to save your first report permanently.")
