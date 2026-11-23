import os
import html
import streamlit as st
from scanner import run_recon, extract_js_endpoints
from analyzer import analyze_recon, save_report
from database import init_db, register_user, authenticate_user, check_and_increment_quota, upgrade_user_to_pro, get_user_status, FREE_MONTHLY_LIMIT
from billing import create_checkout_session, verify_checkout_session, DEV_PROMO_CODE

init_db()
st.set_page_config(page_title="BountyAI Recon SaaS", page_icon="🛡️", layout="wide")

def build_html_report(target: str, markdown_body: str, grade_info: dict) -> str:
    escaped = html.escape(markdown_body)
    grade = grade_info.get("grade", "N/A")
    score = grade_info.get("score", "N/A")
    missing = ", ".join(grade_info.get("missing", [])) or "None"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>BountyAI Report - {html.escape(target)}</title>
<style>body {{ font-family: sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }} .header {{ background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 10px; }} .badge {{ background: #ef4444; color: white; padding: 4px 12px; border-radius: 6px; }} pre {{ white-space: pre-wrap; background: #f8fafc; padding: 20px; border-radius: 8px; }}</style>
</head><body><div class="header"><h1>🛡️ BountyAI Security Report</h1><p><strong>Target:</strong> {html.escape(target)} | <span class="badge">Grade: {grade} ({score})</span></p><p><strong>Missing:</strong> {html.escape(missing)}</p></div><pre>{escaped}</pre></body></html>"""

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
    st.caption("Sign in or create a free account (3 scans/month included) to launch your workspace.")
    tab_login, tab_signup = st.tabs(["🔑 Sign In", "✨ Create Account"])
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
            if st.form_submit_button("Create Free Account", type="primary", use_container_width=True):
                ok, msg = register_user(reg_email, reg_pw)
                st.success(msg + " Switch to Sign In.") if ok else st.error(msg)
    st.stop()
user_info = get_user_status(st.session_state["user"]["id"])
tier, used = user_info["tier"], user_info["scans_used"]

with st.sidebar:
    st.subheader(f"👤 {user_info['email']}")
    if tier == "free":
        remaining = max(0, FREE_MONTHLY_LIMIT - used)
        st.info(f"**Plan:** FREE ({remaining}/{FREE_MONTHLY_LIMIT} scans left this month)")
        with st.expander("🚀 Upgrade to Pro ($29.99/mo)", expanded=True):
            if st.button("Checkout with Stripe", type="primary", use_container_width=True):
                ok, res_url = create_checkout_session(user_info["email"], st.session_state["user"]["id"])
                st.markdown(f"[👉 Complete Payment on Stripe]({res_url})") if ok else st.warning(res_url)
            promo = st.text_input("Dev / Promo Code", placeholder="Enter code")
            if st.button("Redeem Code", use_container_width=True):
                if promo.strip() == DEV_PROMO_CODE:
                    upgrade_user_to_pro(st.session_state["user"]["id"])
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
    target_url = st.text_input("Target URL (Authorized Scope Only)", placeholder="http://vulnweb.com")
    if st.button("Run Recon & AI Triage", type="primary", use_container_width=True):
        if not target_url.strip():
            st.warning("Enter a target URL first.")
        else:
            allowed, quota_msg = check_and_increment_quota(st.session_state["user"]["id"])
            if not allowed:
                st.error(quota_msg)
            else:
                with st.spinner("Crawling target, grading headers, and extracting forms/JS..."):
                    recon_data = run_recon(target_url, ctf_mode=ctf_mode, max_pages=max_pages, allow_subdomains=allow_subs)
                g = recon_data.get("security_grade", {})
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Header Grade", f"{g.get('grade', '?')} ({g.get('score', '0/6')})")
                c2.metric("Pages Crawled", len(recon_data["crawled_pages"]))
                c3.metric("Forms Found", len(recon_data["forms"]))
                c4.metric("JS Endpoints", len(recon_data["js_endpoints"]))
                with st.spinner("Generating AI vulnerability triage report..."):
                    try:
                        report_md = analyze_recon(recon_data, api_key=user_api_key)
                        saved_path = save_report(target_url, report_md)
                        st.session_state["last_report"], st.session_state["last_raw"] = report_md, recon_data
                        st.session_state["last_path"], st.session_state["last_target"] = saved_path, target_url
                    except Exception as e:
                        st.error(f"AI Analysis Error: {e}")
    if "last_report" in st.session_state:
        base_name = os.path.basename(st.session_state["last_path"]).replace(".md", "")
        html_export = build_html_report(st.session_state.get("last_target", "target"), st.session_state["last_report"], st.session_state["last_raw"].get("security_grade", {}))
        d1, d2 = st.columns(2)
        d1.download_button("⬇️ Download Markdown (.md)", st.session_state["last_report"], f"{base_name}.md", "text/markdown", use_container_width=True)
        d2.download_button("⬇️ Download Branded HTML (.html)", html_export, f"{base_name}.html", "text/html", use_container_width=True)
        st.markdown(st.session_state["last_report"])
        with st.expander("View Raw Recon JSON"):
            st.json(st.session_state["last_raw"])

with tab_files:
    uploaded = st.file_uploader("Drop a .js, .txt, .json, or .log file", type=["js", "txt", "json", "log"])
    if uploaded is not None:
        raw_text = uploaded.read().decode("utf-8", errors="ignore")
        endpoints = extract_js_endpoints(raw_text) if uploaded.name.endswith(".js") else []
        st.write(f"**File:** `{uploaded.name}` | **Extracted Paths:** {len(endpoints)}")
        if st.button("Analyze Uploaded File with AI"):
            allowed, quota_msg = check_and_increment_quota(st.session_state["user"]["id"])
            if not allowed:
                st.error(quota_msg)
            else:
                with st.spinner("Analyzing file..."):
                    try:
                        st.markdown(analyze_recon({"file": uploaded.name, "paths": endpoints, "preview": raw_text[:15000]}, api_key=user_api_key))
                    except Exception as e:
                        st.error(f"AI Analysis Error: {e}")

with tab_history:
    if os.path.exists("reports") and os.listdir("reports"):
        selected = st.selectbox("Select a report", sorted(os.listdir("reports"), reverse=True))
        if selected:
            content = open(os.path.join("reports", selected), "r", encoding="utf-8").read()
            st.download_button("⬇️ Download Report", content, selected, "text/markdown")
            st.markdown(content)
    else:
        st.info("No reports saved yet.")
