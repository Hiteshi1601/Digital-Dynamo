#!/usr/bin/env python3
import base64
import io
import os
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_file, make_response, render_template_string, redirect, url_for
import jwt
import qrcode

# ---------------------------
# Config
# ---------------------------
APP_SECRET = os.environ.get("APP_SECRET", "change_me")
QR_BASE_URL = os.environ.get("QR_BASE_URL", "http://localhost:5000/p")
TOKEN_EXP_HOURS = int(os.environ.get("TOKEN_EXP_HOURS", "8"))

ROLES = {"ADMIN", "DOCTOR", "NURSE", "BLOOD_BANK", "WORKER"}

app = Flask(__name__)

# ---------------------------
# In-memory data stores (replace with MongoDB or SQL in production)
# ---------------------------
users = {}  # id -> {id,email,name,role,passwordHash(plain for demo)}
patients = {}  # id -> patient dict
prescriptions = {}  # id -> prescription dict
blood_banks = {}  # id -> blood bank dict
email_index = {}  # email -> user_id
qr_index = {}  # qrCodeId -> patient_id

# Seed demo doctor
def seed_demo():
    if "doctor@example.com" not in email_index:
        uid = str(uuid.uuid4())
        users[uid] = {
            "id": uid,
            "email": "doctor@example.com",
            "name": "Demo Doctor",
            "role": "DOCTOR",
            "passwordHash": "password",  # demo only
        }
        email_index["doctor@example.com"] = uid
seed_demo()

# ---------------------------
# Helpers: auth & roles
# ---------------------------
def create_token(user):
    payload = {
        "id": user["id"],
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS)
    }
    return jwt.encode(payload, APP_SECRET, algorithm="HS256")

def parse_token(token):
    return jwt.decode(token, APP_SECRET, algorithms=["HS256"])

def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Unauthorized"}), 401
            token = auth.split(" ", 1)[1]
            try:
                payload = parse_token(token)
            except Exception:
                return jsonify({"error": "Invalid token"}), 401
            if roles and payload.get("role") not in roles:
                return jsonify({"error": "Forbidden"}), 403
            request.user = {"id": payload["id"], "role": payload["role"]}
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------
# Minimal validators (add robust validation in production)
# ---------------------------
def valid_blood_group(bg):
    return bg in ["A+","A-","B+","B-","AB+","AB-","O+","O-"]

# ---------------------------
# Drug interaction stub
# ---------------------------
CONTRA = {
    "ibuprofen": ["warfarin", "aspirin"],
    "metformin": ["contrast dye"],
    "clarithromycin": ["simvastatin"],
}
def check_interactions(drugs):
    alerts = []
    lower = [d.strip().lower() for d in drugs if d.strip()]
    for i in range(len(lower)):
        for j in range(i+1, len(lower)):
            a, b = lower[i], lower[j]
            if a in CONTRA and b in CONTRA[a] or b in CONTRA and a in CONTRA[b]:
                alerts.append({
                    "a": a, "b": b,
                    "level": "contraindicated",
                    "message": f"Avoid combining {a} and {b}"
                })
    return alerts

# ---------------------------
# QR generation
# ---------------------------
def generate_qr_data_url(qr_code_id: str) -> str:
    url = f"{QR_BASE_URL}/{qr_code_id}"
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"

# ---------------------------
# Routes: Auth
# ---------------------------
@app.post("/api/auth/register")
def register():
    body = request.get_json(force=True)
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    role = body.get("role", "")
    name = body.get("name", "")
    if not email or not password or role not in ROLES or not name:
        return jsonify({"error": "Invalid payload"}), 400
    if email in email_index:
        return jsonify({"error": "Email exists"}), 409
    uid = str(uuid.uuid4())
    users[uid] = {"id": uid, "email": email, "name": name, "role": role, "passwordHash": password}
    email_index[email] = uid
    return jsonify({"id": uid})

@app.post("/api/auth/login")
def login():
    body = request.get_json(force=True)
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    uid = email_index.get(email)
    if not uid:
        return jsonify({"error": "Invalid credentials"}), 401
    user = users[uid]
    if user["passwordHash"] != password:  # demo only
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_token(user)
    return jsonify({"token": token, "role": user["role"], "name": user["name"]})

@app.get("/health")
def health():
    return jsonify({"ok": True, "time": int(time.time())})

# ---------------------------
# Routes: Patients
# ---------------------------
@app.post("/api/patients")
@require_auth(roles={"ADMIN","DOCTOR","NURSE"})
def create_patient():
    body = request.get_json(force=True)
    workerId = body.get("workerId")
    qrCodeId = body.get("qrCodeId") or str(uuid.uuid4())[:8].upper()
    name = body.get("name")
    dob = body.get("dob")
    bloodGroup = body.get("bloodGroup")
    if not workerId or not name or not valid_blood_group(bloodGroup):
        return jsonify({"error": "Invalid payload"}), 400
    pid = str(uuid.uuid4())
    patient = {
        "id": pid,
        "workerId": workerId,
        "qrCodeId": qrCodeId,
        "name": name,
        "dob": dob,
        "bloodGroup": bloodGroup,
        "allergies": body.get("allergies", []),
        "medicalHistory": body.get("medicalHistory", []),
        "vaccinations": body.get("vaccinations", []),
        "prescriptions": [],
        "emergencyContacts": body.get("emergencyContacts", []),
        "lastUpdatedBy": request.user["id"],
        "createdAt": datetime.utcnow().isoformat(),
        "updatedAt": datetime.utcnow().isoformat(),
    }
    patients[pid] = patient
    qr_index[qrCodeId] = pid
    return jsonify(patient)

@app.get("/api/patients/search")
@require_auth(roles={"ADMIN","DOCTOR","NURSE"})
def search_patients():
    q = (request.args.get("q") or "").strip().lower()
    res = []
    for p in patients.values():
        if q in (p.get("name","").lower()) or q in (p.get("workerId","").lower()):
            res.append(p)
    return jsonify(res[:20])

@app.get("/api/patients/<pid>")
@require_auth()
def get_patient(pid):
    p = patients.get(pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    # populate last 10 prescriptions
    populated = {**p}
    populated["prescriptions"] = [prescriptions[prid] for prid in p["prescriptions"]][-10:]
    return jsonify(populated)

@app.post("/api/patients/<pid>/prescriptions")
@require_auth(roles={"DOCTOR"})
def add_prescription(pid):
    p = patients.get(pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    body = request.get_json(force=True)
    items = body.get("items", [])
    notes = body.get("notes", "")
    drugs = [i.get("drug","") for i in items]
    alerts = check_interactions(drugs)
    prid = str(uuid.uuid4())
    pres = {
        "id": prid,
        "patient": pid,
        "issuedBy": request.user["id"],
        "items": items,
        "notes": notes,
        "createdAt": datetime.utcnow().isoformat()
    }
    prescriptions[prid] = pres
    p["prescriptions"].append(prid)
    p["lastUpdatedBy"] = request.user["id"]
    p["updatedAt"] = datetime.utcnow().isoformat()
    return jsonify({"prescription": pres, "safetyAlerts": alerts})

# ---------------------------
# Routes: QR
# ---------------------------
@app.get("/api/qr/image/<pid>")
@require_auth()
def qr_image(pid):
    p = patients.get(pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    data_url = generate_qr_data_url(p["qrCodeId"])
    return jsonify({"dataUrl": data_url})

@app.get("/api/qr/resolve/<qr_code_id>")
def qr_resolve(qr_code_id):
    pid = qr_index.get(qr_code_id)
    if not pid:
        return jsonify({"error": "Not found"}), 404
    p = patients[pid]
    # minimal profile for emergency
    recent = []
    if p["prescriptions"]:
        last_id = p["prescriptions"][-1]
        recent = [prescriptions[last_id]]
    return jsonify({
        "name": p["name"],
        "bloodGroup": p["bloodGroup"],
        "allergies": p.get("allergies", []),
        "emergencyContacts": p.get("emergencyContacts", []),
        "recentPrescriptions": recent
    })

# ---------------------------
# Routes: Blood bank
# ---------------------------
@app.post("/api/blood/banks")
@require_auth(roles={"ADMIN","BLOOD_BANK"})
def add_blood_bank():
    body = request.get_json(force=True)
    name = body.get("name")
    district = body.get("district")
    contact = body.get("contact", {})
    inventory = body.get("inventory", [])
    if not name or not district:
        return jsonify({"error": "Invalid payload"}), 400
    bid = str(uuid.uuid4())
    bank = {
        "id": bid,
        "name": name,
        "district": district,
        "contact": contact,
        "inventory": inventory,
        "createdAt": datetime.utcnow().isoformat(),
        "updatedAt": datetime.utcnow().isoformat(),
    }
    blood_banks[bid] = bank
    return jsonify(bank)

@app.get("/api/blood/availability")
@require_auth()
def blood_availability():
    district = request.args.get("district")
    bloodGroup = request.args.get("bloodGroup")
    if not district or not valid_blood_group(bloodGroup):
        return jsonify({"error": "Invalid query"}), 400
    results = []
    for b in blood_banks.values():
        if b["district"].lower() == district.lower():
            inv = next((i for i in b.get("inventory", []) if i.get("bloodGroup") == bloodGroup), None)
            units = inv.get("unitsAvailable", 0) if inv else 0
            updated = inv.get("lastUpdated") if inv else b.get("updatedAt")
            results.append({
                "id": b["id"],
                "name": b["name"],
                "contact": b.get("contact", {}),
                "units": units,
                "updated": updated
            })
    return jsonify(results)

# ---------------------------
# Simple scan page (HTML)
# ---------------------------
SCAN_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>MediQR Scan</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    body { font-family: system-ui, Arial; margin: 20px; }
    input, button { padding: 10px; margin: 5px 0; width: 100%; max-width: 520px; }
    .card { border: 1px solid #ddd; padding: 12px; border-radius: 8px; max-width: 640px; }
    ul { padding-left: 18px; }
  </style>
</head>
<body>
  <h2>MediQR – Health in a Scan</h2>
  <p>Paste QR URL or QR Code ID to resolve in emergencies.</p>
  <div class="card">
    <input id="input" placeholder="e.g., http://localhost:5000/p/ABC123 or ABC123" />
    <button onclick="resolve()">Resolve</button>
    <div id="out"></div>
  </div>
  <script>
    async function resolve() {
      const raw = document.getElementById('input').value.trim();
      const parts = raw.split('/');
      const qrId = parts[parts.length-1];
      const res = await fetch(`/api/qr/resolve/${qrId}`);
      const data = await res.json();
      if (data.error) {
        document.getElementById('out').innerHTML = '<p style="color:red">Not found</p>';
        return;
      }
      document.getElementById('out').innerHTML = `
        <h3>${data.name}</h3>
        <p><strong>Blood group:</strong> ${data.bloodGroup}</p>
        <h4>Allergies</h4>
        <ul>${(data.allergies||[]).map(a=>`<li>${a.name||a} ${(a.severity? '('+a.severity+')':'')}</li>`).join('')}</ul>
        <h4>Emergency contacts</h4>
        <ul>${(data.emergencyContacts||[]).map(c=>`<li>${c.name||''}: ${c.phone||''}</li>`).join('')}</ul>
      `;
    }
  </script>
</body>
</html>
"""

@app.get("/")
def home():
    return redirect(url_for("scan_page"))

@app.get("/scan")
def scan_page():
    return render_template_string(SCAN_HTML)

# Public path segment to mimic QR_BASE_URL/p/<id>
@app.get("/p/<qr_code_id>")
def public_qr_redirect(qr_code_id):
    # In a real deployment, serve a landing page; here we redirect to scan page with prefill.
    return redirect(url_for("scan_page") + f"?id={qr_code_id}")

# ---------------------------
# Dev utility: sample data
# ---------------------------
@app.post("/dev/seed")
def dev_seed():
    # Add a blood bank and a patient for quick demo
    # Blood bank
    bid = str(uuid.uuid4())
    blood_banks[bid] = {
        "id": bid,
        "name": "Ernakulam General Blood Bank",
        "district": "Ernakulam",
        "contact": {"phone": "+91-0000000000", "email": "bank@example.com"},
        "inventory": [
            {"bloodGroup": "O+", "unitsAvailable": 12, "lastUpdated": datetime.utcnow().isoformat()},
            {"bloodGroup": "A+", "unitsAvailable": 5, "lastUpdated": datetime.utcnow().isoformat()},
        ],
        "createdAt": datetime.utcnow().isoformat(),
        "updatedAt": datetime.utcnow().isoformat(),
    }
    # Patient
    pid = str(uuid.uuid4())
    qrCodeId = "ABC123"
    patients[pid] = {
        "id": pid,
        "workerId": "W-0001",
        "qrCodeId": qrCodeId,
        "name": "Rakesh Kumar",
        "dob": "1990-01-01",
        "bloodGroup": "O+",
        "allergies": [{"name":"Penicillin","severity":"severe"}],
        "medicalHistory": ["Hypertension"],
        "vaccinations": [{"name":"Tetanus","date":"2023-08-10","lot":"TK-11"}],
        "prescriptions": [],
        "emergencyContacts": [{"name":"Suman","relation":"Brother","phone":"+91-98xxxxxx"}],
        "lastUpdatedBy": None,
        "createdAt": datetime.utcnow().isoformat(),
        "updatedAt": datetime.utcnow().isoformat(),
    }
    qr_index[qrCodeId] = pid
    return jsonify({"ok": True})

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    # Run: APP_SECRET=changeme python app.py
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))