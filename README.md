# 🛡️ BountyAI — AI-Powered Web Recon & Vulnerability Triage

**Live App:** [Launch BountyAI SaaS](https://streamlit.app)

BountyAI automates attack-surface mapping, technology fingerprinting, JavaScript endpoint/secret extraction, and AI-prioritized manual testing plans for authorized bug bounty hunters, penetration testers, and CTF players.

## Key Features
- **Automated Attack-Surface Crawling:** Discovers internal links, HTML forms, URL query parameters, and subdomains (`crt.sh`).
- **JS Bundle & Secret Scanner:** Extracts hidden API routes (`/api/...`, `/rest/...`) and flags potential leaked tokens (AWS, Stripe, Google API keys, JWTs).
- **Security Header Grading (A–F) & Tech Fingerprinting:** Audits `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, and detects underlying frameworks.
- **AI Vulnerability Triage & Multi-Format Exports:** Generates prioritized testing roadmaps (SQLi, XSS, IDOR, Auth Bypass) exportable as **Markdown (`.md`)**, **Branded HTML (`.html`)**, and **Client PDF (`.pdf`)**.

## Proof of Concept (OWASP Juice Shop)
- 📄 **[View Full OWASP Juice Shop AI Triage Report](showcase/juice_shop_poc_report.md)**

> **Disclaimer:** BountyAI is strictly intended for authorized security testing, bug bounty programs with explicit written scope, and educational CTF environments.
