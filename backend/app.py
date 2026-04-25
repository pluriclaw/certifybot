from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import random

app = FastAPI(title="CertifyBot")

BACKEND_DIR = Path(__file__).parent
ROOT_DIR = BACKEND_DIR.parent
LANDING_PAGE = ROOT_DIR / "landing.html"

app.add_middleware(CORSMiddleware, allow_origins=["*"])

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
    "quickbooks一类.com": {
        "name": "QuickBooks Clone", "domain": "quickbooks一类.com", "score": 31,
        "rating": "F", "risk": "high",
        "certs": [],
        "bdns_score": 18, "open_ports": 47, "last_audit": "none",
        "verdict": "❌ Not approved — no public certs, typosquatting domain, suspicious",
        "flags": ["Typosquatting domain", "Zero certificates", "47 open ports", "No audit trail"]
    },
}

class ReviewRequest(BaseModel):
    vendor: str

@app.get("/")
def root():
    return FileResponse(LANDING_PAGE)


@app.get("/api/vendors")
def list_vendors():
    return {"vendors": list(DEMO_VENDORS.keys())}

@app.post("/api/review")
def review_vendor(req: ReviewRequest):
    v = DEMO_VENDORS.get(req.vendor.lower())
    if not v:
        # Try partial match
        for key in DEMO_VENDORS:
            if key.lower() in req.vendor.lower() or req.vendor.lower() in key.lower():
                v = DEMO_VENDORS[key]
                break
    if v:
        return {"vendor": v}
    # Generate dynamic response for unknown vendor
    score = random.randint(40, 85)
    rating = "A" if score > 80 else "B" if score > 65 else "C" if score > 50 else "D"
    risk = "low" if score > 70 else "medium" if score > 45 else "high"
    return {
        "vendor": {
            "name": req.vendor, "domain": req.vendor,
            "score": score, "rating": rating, "risk": risk,
            "certs": ["SOC 2 Type II"] if score > 60 else [],
            "bdns_score": score - random.randint(0, 10),
            "open_ports": random.randint(2, 20),
            "last_audit": "2024-" + str(random.randint(1, 12)).zfill(2),
            "verdict": "✅ Approved" if score > 70 else "⚠️ Needs review" if score > 45 else "❌ Not approved",
            "flags": []
        }
    }