import json
import ssl
import socket
import subprocess
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi import HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI(title="CertifyBot")

BACKEND_DIR = Path(__file__).parent
ROOT_DIR = BACKEND_DIR.parent
LANDING_PAGE = ROOT_DIR / "landing.html"

app.add_middleware(CORSMiddleware, allow_origins=["*"])

# ── Security check helpers ──────────────────────────────────────

def grade_for_score(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 90: return "A"
    if score >= 85: return "A-"
    if score >= 80: return "B+"
    if score >= 75: return "B"
    if score >= 70: return "B-"
    if score >= 65: return "C+"
    if score >= 60: return "C"
    if score >= 55: return "C-"
    if score >= 50: return "D"
    return "F"

def risk_for_score(score: int) -> str:
    if score >= 70: return "low"
    if score >= 45: return "medium"
    return "high"

# SSL/TLS analysis via direct socket + cert parsing
def get_ssl_info(domain: str) -> dict:
    result = {
        "has_ssl": False,
        "self_signed": False,
        "valid_months": 0,
        "issuer": "unknown",
        "cn": "",
        "sans": [],
        "protocols": [],
        "cipher": "unknown",
    }
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["has_ssl"] = True
                # Parse not_before / not_after
                if cert and "notAfter" in cert:
                    expiry_str = cert["notAfter"]
                    try:
                        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    except ValueError:
                        try:
                            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y")
                            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                        except ValueError:
                            expiry_dt = None
                    if expiry_dt:
                        now = datetime.now(timezone.utc)
                        delta = expiry_dt - now
                        result["valid_months"] = max(0, int(delta.days / 30))
                        result["expired"] = delta.days < 0
                # Subject CN
                if cert and "subject" in cert:
                    for rdn in cert["subject"]:
                        for k, v in rdn:
                            if k == "commonName":
                                result["cn"] = v
                # SANs
                if cert and "subjectAltName" in cert:
                    result["sans"] = [v for _, v in cert["subjectAltName"]]
                # Issuer
                if cert and "issuer" in cert:
                    for rdn in cert["issuer"]:
                        for k, v in rdn:
                            if k == "organizationName":
                                result["issuer"] = v
                # Cipher
                cipher = ssock.cipher()
                if cipher:
                    result["protocols"] = [cipher[0]]
                    result["cipher"] = cipher[2]
                # Self-signed: issuer == subject
                subject_cns = []
                issuer_org = None
                sub_org = None
                if cert:
                    for rdn in cert.get("subject", []):
                        for k, v in rdn:
                            if k == "organizationName":
                                sub_org = v
                    for rdn in cert.get("issuer", []):
                        for k, v in rdn:
                            if k == "organizationName":
                                issuer_org = v
                    result["self_signed"] = (sub_org == issuer_org and sub_org is not None)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, ssl.SSLError, OSError) as e:
        result["error"] = str(e)
    return result

# Security headers via curl
def get_security_headers(domain: str) -> dict:
    headers = {
        "strict-transport-security": None,
        "content-security-policy": None,
        "x-frame-options": None,
        "x-content-type-options": None,
        "referrer-policy": None,
        "permissions-policy": None,
        "x-xss-protection": None,
        "cache-control": None,
    }
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", "10", "-I",
             f"https://{domain}/"],
            capture_output=True, text=True, timeout=12
        )
        for line in proc.stdout.splitlines():
            for key in headers:
                if line.lower().startswith(key.lower() + ":"):
                    headers[key] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return headers

# crt.sh certificate transparency lookup
def crtsh_lookup(domain: str) -> list:
    results = []
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", "15", "-A", "CertifyBot/1.0", url],
            capture_output=True, text=True, timeout=18
        )
        if proc.returncode == 0 and proc.stdout.strip():
            entries = json.loads(proc.stdout)
            for entry in entries[:50]:
                not_before = entry.get("not_before", "")
                not_after = entry.get("not_after", "")
                issuer = entry.get("issuer_name", "unknown")
                name_value = entry.get("name_value", "")
                results.append({
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "names": name_value.split("\n") if name_value else [],
                })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        pass
    return results

# Tech detection via homepage HTML
def detect_tech(domain: str) -> list:
    techs = []
    try:
        proc = subprocess.run(
            ["curl", "-sS", "--max-time", "10", "-L", "-A",
             "Mozilla/5.0 (CertifyBot Scanner)", f"https://{domain}/"],
            capture_output=True, text=True, timeout=12
        )
        if proc.returncode == 0:
            html = proc.stdout.lower()
            # JS frameworks
            if "react" in html and ("react" in html or "react-dom" in html): techs.append("React")
            if "vue" in html and ("vuejs" in html or "vue." in html): techs.append("Vue.js")
            if "angular" in html: techs.append("Angular")
            if "next.js" in html or "__next" in html: techs.append("Next.js")
            if "nuxt" in html: techs.append("Nuxt.js")
            if "svelte" in html: techs.append("Svelte")
            if "jquery" in html: techs.append("jQuery")
            # CDN / fonts
            if "cdnjs" in html or "cdn.jsdelivr" in html: techs.append("CDN (jsDelivr/CDNJS)")
            if "unpkg.com" in html: techs.append("CDN (unpkg)")
            if "google Tag Manager" in html or "googletagmanager" in html: techs.append("Google Tag Manager")
            if "google-analytics" in html or "gtag(" in html: techs.append("Google Analytics")
            if "plausible" in html: techs.append("Plausible Analytics")
            if "segment" in html: techs.append("Segment")
            if "cloudflare" in html or "cloudflare.com" in html: techs.append("Cloudflare")
            if "akamai" in html: techs.append("Akamai")
            if "fastly" in html: techs.append("Fastly")
            # Security / misc
            if "stripe.com" in html or "js.stripe.com" in html: techs.append("Stripe")
            if "braintree" in html: techs.append("Braintree")
            if "paypal.com" in html: techs.append("PayPal")
            if "hotjar" in html: techs.append("Hotjar")
            if "intercom" in html: techs.append("Intercom")
            if "zendesk" in html: techs.append("Zendesk")
            if "hubspot" in html: techs.append("HubSpot")
            if "marketo" in html: techs.append("Marketo")
            if "mailchimp" in html: techs.append("Mailchimp")
            # Web servers
            if "nginx" in html: techs.append("nginx")
            if "apache" in html: techs.append("Apache")
            if "cloudflare" in html: techs.append("Cloudflare")
            # WordPress specific
            if 'wp-content' in html or 'wp-includes' in html: techs.append("WordPress")
            if "wix" in html: techs.append("Wix")
            if "squarespace" in html: techs.append("Squarespace")
            if "shopify" in html: techs.append("Shopify")
            if "webflow" in html: techs.append("Webflow")
            # Modern frameworks
            if "__nuxt" in html: techs.append("Nuxt.js")
            if "__NEXT_DATA__" in html: techs.append("Next.js")
            if "gatsby" in html: techs.append("Gatsby")
            if "astro" in html: techs.append("Astro")
    except Exception:
        pass
    return list(set(techs))

# Compute security score
def compute_score(ssl_info: dict, headers: dict, crt_data: list, techs: list) -> tuple[int, list]:
    score = 100
    flags = []
    findings = []

    # SSL/TLS (up to -35 points)
    if not ssl_info.get("has_ssl"):
        score -= 40
        flags.append("No HTTPS — unencrypted connection")
        findings.append({"category": "TLS/SSL", "severity": "critical", "message": "No SSL certificate detected", "points": -40})
    else:
        if ssl_info.get("self_signed"):
            score -= 15
            flags.append("Self-signed certificate")
            findings.append({"category": "TLS/SSL", "severity": "high", "message": "Self-signed certificate", "points": -15})
        if ssl_info.get("expired"):
            score -= 20
            flags.append("Certificate expired")
            findings.append({"category": "TLS/SSL", "severity": "critical", "message": "SSL certificate has expired", "points": -20})
        elif ssl_info.get("valid_months", 0) == 0:
            score -= 10
            flags.append("Certificate expires soon")
            findings.append({"category": "TLS/SSL", "severity": "medium", "message": "SSL certificate expires within 30 days", "points": -10})
        elif ssl_info.get("valid_months", 0) < 3:
            score -= 5
            flags.append("Certificate expires within 3 months")
            findings.append({"category": "TLS/SSL", "severity": "low", "message": "SSL certificate expires within 3 months", "points": -5})

        # Weak ciphers
        cipher = ssl_info.get("cipher", "")
        weak_ciphers = ["rc4", "des", "3des", "md5", "tls_1.0", "tls_1.1"]
        if any(w in cipher.lower() for w in weak_ciphers):
            score -= 10
            flags.append(f"Weak cipher: {cipher}")
            findings.append({"category": "TLS/SSL", "severity": "high", "message": f"Weak TLS cipher: {cipher}", "points": -10})

    # Security headers (up to -35 points)
    header_checks = [
        ("strict-transport-security", "HSTS", 10),
        ("content-security-policy", "CSP", 10),
        ("x-frame-options", "X-Frame-Options", 5),
        ("x-content-type-options", "X-Content-Type-Options", 5),
        ("referrer-policy", "Referrer-Policy", 3),
        ("permissions-policy", "Permissions-Policy", 2),
    ]
    present_headers = []
    missing_headers = []
    for hdr_key, hdr_name, pts in header_checks:
        if headers.get(hdr_key):
            present_headers.append(hdr_name)
            if hdr_key == "strict-transport-security":
                hsts_val = headers[hdr_key].lower()
                if "max-age" in hsts_val:
                    try:
                        max_age = int(re.search(r"max-age=(\d+)", hsts_val).group(1))
                        if max_age < 31536000:
                            score -= 3
                            findings.append({"category": "Headers", "severity": "low", "message": "HSTS max-age too short (< 1 year)", "points": -3})
                        if "includeSubDomains" in hsts_val:
                            score += 3  # bonus
                    except Exception:
                        pass
        else:
            missing_headers.append(hdr_name)
            score -= pts
            findings.append({"category": "Headers", "severity": "medium" if pts >= 5 else "low", "message": f"Missing {hdr_name} header", "points": -pts})

    # crt.sh cert count
    if crt_data:
        issuer_counts = Counter(e["issuer"] for e in crt_data)
        total_certs = len(crt_data)
        findings.append({"category": "Certificate Transparency", "severity": "info", "message": f"{total_certs} certificates in CT log from {len(issuer_counts)} issuer(s)", "points": 0})
    else:
        flags.append("No certificate transparency data (possible concern)")
        findings.append({"category": "Certificate Transparency", "severity": "low", "message": "No certificates found in crt.sh CT log", "points": -5})

    # Technology stack (up to -10 points)
    legacy = ["jquery", "angularjs"]
    modern = ["react", "vue.js", "next.js", "nuxt.js", "svelte", "gatsby", "astro"]
    has_legacy = any(t.lower() in legacy for t in techs)
    has_modern = any(t in techs for t in modern)

    if has_legacy:
        score -= 8
        findings.append({"category": "Tech Stack", "severity": "medium", "message": "Legacy JavaScript framework detected (jQuery/AngularJS)", "points": -8})
    elif not techs:
        score -= 3
        findings.append({"category": "Tech Stack", "severity": "low", "message": "Could not detect technology stack", "points": -3})

    if has_modern:
        score += 3  # small bonus for modern stack
        findings.append({"category": "Tech Stack", "severity": "info", "message": "Modern JS framework detected", "points": +3})

    score = max(0, min(100, score))
    return score, flags, findings, present_headers, missing_headers

# Verdict text
def make_verdict(score: int, flags: list) -> str:
    if score >= 80 and not flags:
        return "✅ Approved — strong security posture"
    elif score >= 80:
        return "✅ Approved — good security posture with minor notes"
    elif score >= 65:
        return "⚠️ Conditional approval — review flags before proceeding"
    elif score >= 45:
        return "⚠️ Needs review — significant security gaps found"
    else:
        return "❌ Not approved — critical security issues"

# ── FastAPI models ───────────────────────────────────────────────

class CheckRequest(BaseModel):
    domain: str

# ── Routes ───────────────────────────────────────────────────────

@app.get("/")
def root():
    return FileResponse(LANDING_PAGE)

@app.post("/api/check")
def check_domain(req: CheckRequest):
    domain = req.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")

    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # 1. SSL/TLS info
    ssl_info = get_ssl_info(domain)

    # 2. Security headers
    headers = get_security_headers(domain)

    # 3. crt.sh lookup (fire-and-forget, don't block on it)
    crt_data = crtsh_lookup(domain)

    # 4. Technology detection
    techs = detect_tech(domain)

    # 5. Score
    score, flags, findings, present_headers, missing_headers = compute_score(ssl_info, headers, crt_data, techs)
    rating = grade_for_score(score)
    risk = risk_for_score(score)
    verdict = make_verdict(score, flags)

    # Summarize certificates from crt.sh
    cert_summaries = []
    if crt_data:
        seen_issuers = set()
        for e in crt_data:
            issuer = e["issuer"]
            if issuer not in seen_issuers:
                seen_issuers.add(issuer)
                cert_summaries.append(issuer)

    return {
        "domain": domain,
        "score": score,
        "rating": rating,
        "risk": risk,
        "verdict": verdict,
        "ssl": {
            "has_ssl": ssl_info.get("has_ssl", False),
            "valid_months": ssl_info.get("valid_months", 0),
            "self_signed": ssl_info.get("self_signed", False),
            "issuer": ssl_info.get("issuer", "unknown"),
            "cn": ssl_info.get("cn", ""),
            "cipher": ssl_info.get("cipher", "unknown"),
            "expired": ssl_info.get("expired", None),
        },
        "headers": {
            "present": present_headers,
            "missing": missing_headers,
        },
        "certificates": cert_summaries[:8],
        "tech_stack": techs,
        "flags": flags,
        "findings": findings,
    }

# Keep /api/review for backwards compatibility with demo buttons
class ReviewRequest(BaseModel):
    vendor: str

DEMO_VENDORS = {
    "stripe.com": {
        "name": "Stripe", "domain": "stripe.com", "score": 94,
        "rating": "A+", "risk": "low",
        "certs": ["PCI DSS Level 1", "SOC 2 Type II", "ISO 27001"],
        "bdns_score": 98, "open_ports": 2, "last_audit": "2025-09",
        "verdict": "✅ Approved — strong security posture, PCI compliant",
        "flags": []
    },
    "sendgrid.com": {
        "name": "SendGrid", "domain": "sendgrid.com", "score": 87,
        "rating": "A-", "risk": "low",
        "certs": ["SOC 2 Type II", "ISO 27001", "HIPAA BAA"],
        "bdns_score": 91, "open_ports": 4, "last_audit": "2025-03",
        "verdict": "✅ Approved — good security posture, email-specific certs in order",
        "flags": ["Email gateway — monitor for spoofing"]
    },
    "datadog.com": {
        "name": "Datadog", "domain": "datadog.com", "score": 91,
        "rating": "A", "risk": "low",
        "certs": ["SOC 2 Type II", "ISO 27001", "FedRAMP Authorized"],
        "bdns_score": 95, "open_ports": 6, "last_audit": "2025-06",
        "verdict": "✅ Approved — comprehensive cert coverage, monitoring-in-place",
        "flags": ["High attack surface due to agent ports — monitor agent communications"]
    },
    "invensis.com": {
        "name": "Invensis BPO", "domain": "invensis.com", "score": 58,
        "rating": "C", "risk": "medium",
        "certs": ["SOC 2 Type I", "ISO 27001 (expired)"],
        "bdns_score": 62, "open_ports": 18, "last_audit": "2022-11",
        "verdict": "⚠️ Needs review — some certs expired, high port count, old audit",
        "flags": ["ISO 27001 expired", "18 open ports (unusual)", "Audit > 2 years old"]
    },
    "quickbooks四类.com": {
        "name": "QuickBooks Clone", "domain": "quickbooks四类.com", "score": 31,
        "rating": "F", "risk": "high",
        "certs": [],
        "bdns_score": 18, "open_ports": 47, "last_audit": "none",
        "verdict": "❌ Not approved — no public certs, typosquatting domain, suspicious",
        "flags": ["Typosquatting domain", "Zero certificates", "47 open ports", "No audit trail"]
    },
}

@app.get("/api/vendors")
def list_vendors():
    return {"vendors": list(DEMO_VENDORS.keys())}

@app.post("/api/review")
def review_vendor(req: ReviewRequest):
    v = DEMO_VENDORS.get(req.vendor.lower())
    if not v:
        for key in DEMO_VENDORS:
            if key.lower() in req.vendor.lower() or req.vendor.lower() in key.lower():
                v = DEMO_VENDORS[key]
                break
    if v:
        return {"vendor": v}
    return {"vendor": None, "message": "Vendor not found in demo set. Try the live check below."}

# ── Waitlist ─────────────────────────────────────────────────────

WAITLIST_FILE = BACKEND_DIR / "waitlist.json"

def load_waitlist():
    if not WAITLIST_FILE.exists():
        return []
    return json.loads(WAITLIST_FILE.read_text())

def save_waitlist(entries):
    WAITLIST_FILE.write_text(json.dumps(entries, indent=2, ensure_ascii=False))

class WaitlistEntry(BaseModel):
    email: str
    company: str | None = None

@app.post("/api/waitlist", status_code=201)
def join_waitlist(entry: WaitlistEntry):
    waitlist = load_waitlist()
    for existing in waitlist:
        if existing["email"] == entry.email:
            return {"message": "already_registered", "email": entry.email}
    record = {"email": entry.email, "company": entry.company or "", "joined_at": datetime.now().isoformat()}
    waitlist.append(record)
    save_waitlist(waitlist)
    return {"message": "added", "email": entry.email, "count": len(waitlist)}
