#!/usr/bin/env python3
"""
Shanghai X Run 2026 - Backend Completo v4.0
Nuove feature: Pettorali con QR, Adozioni, Nomi Percorsi Custom, Instagram, Push Notifications
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
import jwt
import bcrypt
import os
import json
import uuid
import gpxpy
import gpxpy.gpx
from shapely.geometry import Point, LineString
from shapely.ops import nearest_points
import asyncio
from collections import defaultdict
import io
import csv
import qrcode
import requests

# ============================================================================
# CONFIGURATION
# ============================================================================

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 30  # 30 days

STRAVA_CLIENT_ID = os.getenv("STRAVA_CLIENT_ID", "")
STRAVA_CLIENT_SECRET = os.getenv("STRAVA_CLIENT_SECRET", "")
EXPO_PUSH_TOKEN_URL = "https://exp.host/--/api/v2/push/send"
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:19006")

# Event configuration
EVENT_DATE = datetime(2026, 5, 10, 9, 0, 0)
EVENT_LOCATION = {"lat": 43.2055, "lng": 11.4462}
DONATION_TARGET = 20000

# Geofence
START_LINE = {"lat": 43.2055, "lng": 11.4462, "radius_m": 50}
FINISH_LINE = {"lat": 43.2055, "lng": 11.4462, "radius_m": 50}

# Bib reservation timeout (10 minutes)
BIB_RESERVATION_TIMEOUT_MINUTES = 10

# ============================================================================
# MODELS
# ============================================================================

class UserRole(str, Enum):
    ADMIN = "admin"
    RUNNER = "runner"
    SPECTATOR = "spectator"

class BibStatus(str, Enum):
    DISPONIBILE = "disponibile"
    RISERVATO = "riservato"
    ASSEGNATO = "assegnato"

class PaymentMethod(str, Enum):
    PAYPAL = "paypal"
    SATISPAY = "satispay"
    BONIFICO = "bonifico"
    CONTANTI = "contanti"

class PaymentStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

class RunnerStatus(str, Enum):
    REGISTERED = "registered"
    READY = "ready"
    RUNNING = "running"
    FINISHED = "finished"
    DNF = "dnf"

class RouteType(str, Enum):
    KM_5 = "5km"
    KM_10 = "10km"
    KM_21 = "21km"

class AdoptionType(str, Enum):
    BIB = "bib"           # Adotta pettorale €15
    RUNNER = "runner"      # Adotta corridore €20
    KM = "km"             # Adotta chilometro €50
    FREE = "free"         # Donazione libera da €5

# Pydantic Models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: UserRole
    # Personal info
    nome: Optional[str] = None
    cognome: Optional[str] = None
    data_nascita: Optional[str] = None
    telefono: Optional[str] = None
    # Runner-specific
    percorso: Optional[RouteType] = None
    interessi: Optional[List[str]] = []
    selfie_url: Optional[str] = None
    bio: Optional[str] = None
    # Consents
    consent_gps: Optional[bool] = False
    consent_gdpr: Optional[bool] = False
    consent_rules: Optional[bool] = False
    consent_liability: Optional[bool] = False
    # Strava
    strava_connect: Optional[bool] = False
    strava_user_id: Optional[str] = None
    strava_access_token: Optional[str] = None
    strava_refresh_token: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class BibReserveRequest(BaseModel):
    bib_number: int

class BibAssignRequest(BaseModel):
    bib_number: int
    user_id: Optional[str] = None
    payment_proof_url: Optional[str] = None

class BibScanQRRequest(BaseModel):
    qr_code: str
    user_id: Optional[str] = None

class AdoptionRequest(BaseModel):
    type: AdoptionType
    amount: float
    target_id: Optional[str] = None  # runner_id or km_number or null
    dedication: Optional[str] = None
    payment_method: PaymentMethod

class RouteUpdateRequest(BaseModel):
    display_name: str
    description: Optional[str] = None

class EventConfigRequest(BaseModel):
    name: Optional[str] = None
    date: Optional[str] = None
    location: Optional[str] = None
    donation_target: Optional[float] = None
    description: Optional[str] = None
    rules: Optional[str] = None

class PaymentConfig(BaseModel):
    paypal_link: Optional[str] = None
    satispay_link: Optional[str] = None
    iban: Optional[str] = None
    bic: Optional[str] = None
    intestatario: Optional[str] = None
    enable_cash: bool = True

class SocialConfig(BaseModel):
    instagram_url: Optional[str] = None
    facebook_url: Optional[str] = None
    twitter_url: Optional[str] = None

class SponsorRequest(BaseModel):
    name: str
    logo_url: str
    website: Optional[str] = None
    donation_amount: float = 0

class PushNotificationRequest(BaseModel):
    title: str
    body: str
    target_role: Optional[UserRole] = None
    data: Optional[Dict[str, Any]] = {}

class DeviceTokenRequest(BaseModel):
    token: str
    platform: str = "ios"  # ios or android

class GPSUpdate(BaseModel):
    lat: float
    lng: float
    timestamp: Optional[str] = None
    accuracy: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None

class PhotoUpload(BaseModel):
    photo_url: str
    caption: Optional[str] = ""
    km_marker: Optional[float] = None

class MatchRequest(BaseModel):
    target_user_id: str

class ChatMessage(BaseModel):
    channel: str
    message: str

class POI(BaseModel):
    name: str
    type: str
    lat: float
    lng: float
    km_marker: Optional[float] = None
    description: Optional[str] = ""

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Shanghai X Run 2026 API",
    version="4.0",
    description="Backend completo con pettorali QR, adozioni, push notifications"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# MongoDB
db_client: Optional[AsyncIOMotorClient] = None
db = None

# WebSocket connections
ws_connections: Dict[str, List[WebSocket]] = defaultdict(list)

# In-memory race state
race_state = {
    "active_runners": {},
    "leaderboard": [],
}

# ============================================================================
# DATABASE HELPERS
# ============================================================================

async def get_collection(name: str):
    return db[name]

@app.on_event("startup")
async def startup_db():
    global db_client, db
    db_client = AsyncIOMotorClient(MONGO_URL)
    db = db_client["shanghai_x_run"]
    
    # Create indexes
    users_col = await get_collection("users")
    await users_col.create_index("email", unique=True)
    
    bibs_col = await get_collection("bibs")
    await bibs_col.create_index("number", unique=True)
    await bibs_col.create_index("status")
    
    # Initialize 500 bibs
    existing = await bibs_col.count_documents({})
    if existing == 0:
        bibs = [{"number": i, "status": BibStatus.DISPONIBILE, "user_id": None, "reserved_at": None, "assigned_at": None, "qr_code": f"BIB_{i:03d}", "picked_up": False} for i in range(1, 501)]
        await bibs_col.insert_many(bibs)
    
    print("✅ Database initialized: 500 bibs created")

@app.on_event("shutdown")
async def shutdown_db():
    if db_client:
        db_client.close()

# ============================================================================
# AUTH HELPERS
# ============================================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_jwt(user_id: str, email: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        users_col = await get_collection("users")
        user = await users_col.find_one({"_id": payload["user_id"]})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

async def require_admin(user = Depends(get_current_user)):
    if user.get("role") != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ============================================================================
# BIB SYSTEM
# ============================================================================

async def release_expired_reservations():
    """Background task: release bibs reserved >10 min ago"""
    bibs_col = await get_collection("bibs")
    timeout = datetime.utcnow() - timedelta(minutes=BIB_RESERVATION_TIMEOUT_MINUTES)
    result = await bibs_col.update_many(
        {"status": BibStatus.RISERVATO, "reserved_at": {"$lt": timeout}},
        {"$set": {"status": BibStatus.DISPONIBILE, "user_id": None, "reserved_at": None}}
    )
    if result.modified_count > 0:
        print(f"Released {result.modified_count} expired bib reservations")

@app.get("/api/bibs/availability")
async def get_bibs_availability(page: int = 1, per_page: int = 100):
    """Get bib availability (paginated 100 per page, max 5 pages for 500 bibs)"""
    await release_expired_reservations()
    
    bibs_col = await get_collection("bibs")
    skip = (page - 1) * per_page
    
    bibs = await bibs_col.find({}).sort("number", 1).skip(skip).limit(per_page).to_list(per_page)
    total = await bibs_col.count_documents({})
    
    return {
        "bibs": [{"number": b["number"], "status": b["status"], "picked_up": b.get("picked_up", False)} for b in bibs],
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": (total + per_page - 1) // per_page
    }

@app.post("/api/bibs/reserve")
async def reserve_bib(req: BibReserveRequest, user = Depends(get_current_user)):
    """Reserve bib for 10 minutes (for users paying later)"""
    await release_expired_reservations()
    
    bibs_col = await get_collection("bibs")
    bib = await bibs_col.find_one({"number": req.bib_number})
    
    if not bib:
        raise HTTPException(status_code=404, detail="Bib not found")
    if bib["status"] != BibStatus.DISPONIBILE:
        raise HTTPException(status_code=400, detail=f"Bib {req.bib_number} not available (status: {bib['status']})")
    
    result = await bibs_col.update_one(
        {"number": req.bib_number, "status": BibStatus.DISPONIBILE},
        {"$set": {"status": BibStatus.RISERVATO, "user_id": user["_id"], "reserved_at": datetime.utcnow()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=409, detail="Bib was just taken by another user")
    
    return {"message": f"Bib {req.bib_number} reserved for 10 minutes", "expires_at": datetime.utcnow() + timedelta(minutes=10)}

@app.post("/api/bibs/assign")
async def assign_bib(req: BibAssignRequest, user = Depends(get_current_user)):
    """Assign bib definitively after payment (or admin manual assignment)"""
    bibs_col = await get_collection("bibs")
    users_col = await get_collection("users")
    
    target_user_id = req.user_id if req.user_id and user.get("role") == UserRole.ADMIN else user["_id"]
    
    bib = await bibs_col.find_one({"number": req.bib_number})
    if not bib:
        raise HTTPException(status_code=404, detail="Bib not found")
    
    # Allow if: disponibile OR riservato by same user
    if bib["status"] == BibStatus.ASSEGNATO:
        raise HTTPException(status_code=400, detail=f"Bib {req.bib_number} already assigned")
    if bib["status"] == BibStatus.RISERVATO and bib["user_id"] != target_user_id:
        raise HTTPException(status_code=400, detail=f"Bib {req.bib_number} reserved by another user")
    
    result = await bibs_col.update_one(
        {"number": req.bib_number},
        {"$set": {"status": BibStatus.ASSEGNATO, "user_id": target_user_id, "assigned_at": datetime.utcnow(), "reserved_at": None}}
    )
    
    # Update user bib
    await users_col.update_one(
        {"_id": target_user_id},
        {"$set": {"bib_number": req.bib_number, "payment_status": PaymentStatus.COMPLETED if req.payment_proof_url else PaymentStatus.PENDING, "payment_proof_url": req.payment_proof_url}}
    )
    
    return {"message": f"Bib {req.bib_number} assigned to user {target_user_id}"}

@app.post("/api/bibs/scan-qr")
async def scan_bib_qr(req: BibScanQRRequest, admin = Depends(require_admin)):
    """Scan QR code on physical bib → mark as picked up (check-in day)"""
    bibs_col = await get_collection("bibs")
    users_col = await get_collection("users")
    
    # Extract bib number from QR code (format: BIB_024)
    try:
        bib_number = int(req.qr_code.split("_")[1])
    except:
        raise HTTPException(status_code=400, detail="Invalid QR code format")
    
    bib = await bibs_col.find_one({"number": bib_number})
    if not bib:
        raise HTTPException(status_code=404, detail=f"Bib {bib_number} not found")
    if bib["status"] != BibStatus.ASSEGNATO:
        raise HTTPException(status_code=400, detail=f"Bib {bib_number} not assigned yet")
    
    # Mark picked up
    await bibs_col.update_one(
        {"number": bib_number},
        {"$set": {"picked_up": True, "picked_up_at": datetime.utcnow()}}
    )
    
    # Get user info
    user = await users_col.find_one({"_id": bib["user_id"]})
    
    return {
        "message": f"Bib {bib_number} picked up successfully",
        "bib_number": bib_number,
        "user": {
            "name": f"{user.get('nome', '')} {user.get('cognome', '')}",
            "email": user.get("email"),
            "route": user.get("percorso")
        }
    }

@app.get("/api/admin/bibs/export-csv")
async def export_bibs_csv(admin = Depends(require_admin)):
    """Export all bibs to CSV for organizers"""
    bibs_col = await get_collection("bibs")
    users_col = await get_collection("users")
    
    bibs = await bibs_col.find({"status": BibStatus.ASSEGNATO}).sort("number", 1).to_list(500)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Numero", "Nome", "Cognome", "Email", "Telefono", "Percorso", "Pagato", "Ritirato", "Data Assegnazione"])
    
    for bib in bibs:
        user = await users_col.find_one({"_id": bib["user_id"]})
        if user:
            writer.writerow([
                bib["number"],
                user.get("nome", ""),
                user.get("cognome", ""),
                user.get("email", ""),
                user.get("telefono", ""),
                user.get("percorso", ""),
                "Sì" if user.get("payment_status") == PaymentStatus.COMPLETED else "No",
                "Sì" if bib.get("picked_up") else "No",
                bib.get("assigned_at", "").isoformat() if bib.get("assigned_at") else ""
            ])
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=pettorali_shanghai_x_run.csv"}
    )

@app.get("/api/admin/bibs/qr-codes")
async def generate_qr_codes_pdf(admin = Depends(require_admin)):
    """Generate QR codes for all bibs (for printing on physical bibs)"""
    # TODO: Generate PDF with QR codes using ReportLab
    # For now, return JSON with QR data
    bibs_col = await get_collection("bibs")
    bibs = await bibs_col.find({}).sort("number", 1).to_list(500)
    
    qr_data = []
    for bib in bibs:
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(bib["qr_code"])
        qr.make(fit=True)
        # In production: generate image and add to PDF
        qr_data.append({"number": bib["number"], "qr_code": bib["qr_code"]})
    
    return {"message": "QR codes data generated", "bibs": qr_data, "note": "PDF generation coming soon"}

# ============================================================================
# ADOPTIONS SYSTEM
# ============================================================================

@app.post("/api/adoptions")
async def create_adoption(req: AdoptionRequest, user = Depends(get_current_user)):
    """Create adoption (bib/runner/km/free donation)"""
    adoptions_col = await get_collection("adoptions")
    
    # Validate amounts
    min_amounts = {
        AdoptionType.BIB: 15,
        AdoptionType.RUNNER: 20,
        AdoptionType.KM: 50,
        AdoptionType.FREE: 5
    }
    
    if req.amount < min_amounts[req.type]:
        raise HTTPException(status_code=400, detail=f"Minimum amount for {req.type} is €{min_amounts[req.type]}")
    
    # Generate payment reference
    payment_ref = f"XRUN2026-{req.type.value.upper()}-{uuid.uuid4().hex[:8].upper()}"
    
    adoption = {
        "type": req.type,
        "amount": req.amount,
        "adopter_id": user["_id"],
        "adopter_email": user["email"],
        "target_id": req.target_id,
        "dedication": req.dedication,
        "payment_method": req.payment_method,
        "payment_status": PaymentStatus.PENDING,
        "payment_reference": payment_ref,
        "created_at": datetime.utcnow(),
        "certificate_url": None
    }
    
    result = await adoptions_col.insert_one(adoption)
    adoption["_id"] = str(result.inserted_id)
    
    # Generate payment instructions
    payment_config_col = await get_collection("payment_config")
    config = await payment_config_col.find_one({})
    
    payment_info = {}
    if req.payment_method == PaymentMethod.PAYPAL:
        payment_info = {"url": config.get("paypal_link") if config else None, "reference": payment_ref}
    elif req.payment_method == PaymentMethod.SATISPAY:
        payment_info = {"url": config.get("satispay_link") if config else None, "reference": payment_ref}
    elif req.payment_method == PaymentMethod.BONIFICO:
        payment_info = {
            "iban": config.get("iban") if config else None,
            "bic": config.get("bic") if config else None,
            "intestatario": config.get("intestatario") if config else None,
            "causale": payment_ref
        }
    
    return {
        "adoption_id": adoption["_id"],
        "type": req.type,
        "amount": req.amount,
        "payment_reference": payment_ref,
        "payment_info": payment_info,
        "message": "Adoption created successfully. Complete payment to activate."
    }

@app.get("/api/adoptions/my")
async def get_my_adoptions(user = Depends(get_current_user)):
    """Get user's adoptions"""
    adoptions_col = await get_collection("adoptions")
    adoptions = await adoptions_col.find({"adopter_id": user["_id"]}).to_list(100)
    
    for adoption in adoptions:
        adoption["_id"] = str(adoption["_id"])
        adoption["created_at"] = adoption["created_at"].isoformat()
    
    return {"adoptions": adoptions, "total": len(adoptions)}

@app.get("/api/admin/adoptions")
async def get_all_adoptions(admin = Depends(require_admin)):
    """Get all adoptions (admin)"""
    adoptions_col = await get_collection("adoptions")
    adoptions = await adoptions_col.find({}).sort("created_at", -1).to_list(1000)
    
    for adoption in adoptions:
        adoption["_id"] = str(adoption["_id"])
        adoption["created_at"] = adoption["created_at"].isoformat()
    
    total_amount = sum(a["amount"] for a in adoptions if a["payment_status"] == PaymentStatus.COMPLETED)
    
    return {"adoptions": adoptions, "total": len(adoptions), "total_amount": total_amount}

@app.post("/api/admin/adoptions/{adoption_id}/confirm-payment")
async def confirm_adoption_payment(adoption_id: str, admin = Depends(require_admin)):
    """Manually confirm adoption payment (admin)"""
    adoptions_col = await get_collection("adoptions")
    result = await adoptions_col.update_one(
        {"_id": adoption_id},
        {"$set": {"payment_status": PaymentStatus.COMPLETED, "confirmed_at": datetime.utcnow()}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Adoption not found")
    
    # TODO: Generate certificate, send email notification
    return {"message": "Payment confirmed successfully"}

# ============================================================================
# ROUTES & EVENT CONFIG
# ============================================================================

@app.put("/api/admin/routes/{route_type}")
async def update_route(route_type: RouteType, req: RouteUpdateRequest, admin = Depends(require_admin)):
    """Update route display name (custom names per edition)"""
    routes_col = await get_collection("routes")
    
    result = await routes_col.update_one(
        {"type": route_type},
        {"$set": {"display_name": req.display_name, "description": req.description, "updated_at": datetime.utcnow()}},
        upsert=True
    )
    
    return {"message": f"Route {route_type} updated", "display_name": req.display_name}

@app.get("/api/routes")
async def get_routes():
    """Get all routes with custom names"""
    routes_col = await get_collection("routes")
    routes = await routes_col.find({}).to_list(10)
    
    # Default names if not set
    defaults = {
        RouteType.KM_5: "Percorso 5 KM",
        RouteType.KM_10: "Percorso 10 KM",
        RouteType.KM_21: "Percorso 21 KM (Mezza Maratona)"
    }
    
    result = []
    for route_type in [RouteType.KM_5, RouteType.KM_10, RouteType.KM_21]:
        route = next((r for r in routes if r["type"] == route_type), None)
        result.append({
            "type": route_type,
            "display_name": route["display_name"] if route else defaults[route_type],
            "description": route.get("description") if route else None,
            "gpx_uploaded": route.get("gpx_url") is not None if route else False
        })
    
    return {"routes": result}

@app.get("/api/event")
async def get_event_config():
    """Get event configuration"""
    config_col = await get_collection("event_config")
    config = await config_col.find_one({})
    
    if not config:
        config = {
            "name": "Shanghai X Run 2026",
            "date": "2026-05-10T09:00:00",
            "location": "Castellina Scalo, Siena",
            "donation_target": 20000
        }
    
    config.pop("_id", None)
    return config

@app.put("/api/admin/event")
async def update_event_config(req: EventConfigRequest, admin = Depends(require_admin)):
    """Update event configuration"""
    config_col = await get_collection("event_config")
    
    update_data = {k: v for k, v in req.dict().items() if v is not None}
    update_data["updated_at"] = datetime.utcnow()
    
    await config_col.update_one({}, {"$set": update_data}, upsert=True)
    
    return {"message": "Event config updated", "updated_fields": list(update_data.keys())}

# ============================================================================
# SOCIAL CONFIG (Instagram, Facebook)
# ============================================================================

@app.get("/api/config/social")
async def get_social_config():
    """Get social media links"""
    config_col = await get_collection("social_config")
    config = await config_col.find_one({})
    
    if not config:
        return {"instagram_url": None, "facebook_url": None, "twitter_url": None}
    
    config.pop("_id", None)
    return config

@app.put("/api/admin/config/social")
async def update_social_config(req: SocialConfig, admin = Depends(require_admin)):
    """Update social media links"""
    config_col = await get_collection("social_config")
    
    update_data = {k: v for k, v in req.dict().items() if v is not None}
    update_data["updated_at"] = datetime.utcnow()
    
    await config_col.update_one({}, {"$set": update_data}, upsert=True)
    
    return {"message": "Social config updated"}

# ============================================================================
# PUSH NOTIFICATIONS (Expo)
# ============================================================================

@app.post("/api/notifications/register")
async def register_device_token(req: DeviceTokenRequest, user = Depends(get_current_user)):
    """Register Expo push token for notifications"""
    users_col = await get_collection("users")
    
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {"device_token": req.token, "device_platform": req.platform, "token_updated_at": datetime.utcnow()}}
    )
    
    return {"message": "Device token registered"}

@app.post("/api/admin/notifications/send")
async def send_push_notification(req: PushNotificationRequest, admin = Depends(require_admin)):
    """Send push notification to users (all, runners, spectators)"""
    users_col = await get_collection("users")
    
    # Get target users
    query = {}
    if req.target_role:
        query["role"] = req.target_role
    query["device_token"] = {"$exists": True, "$ne": None}
    
    users = await users_col.find(query).to_list(1000)
    tokens = [u["device_token"] for u in users if u.get("device_token")]
    
    if not tokens:
        return {"message": "No device tokens found", "sent": 0}
    
    # Send via Expo Push API
    notifications = [{
        "to": token,
        "sound": "default",
        "title": req.title,
        "body": req.body,
        "data": req.data
    } for token in tokens]
    
    # Batch send (Expo supports 100 per request)
    sent_count = 0
    for i in range(0, len(notifications), 100):
        batch = notifications[i:i+100]
        try:
            response = requests.post(
                EXPO_PUSH_TOKEN_URL,
                json=batch,
                headers={"Content-Type": "application/json"}
            )
            if response.status_code == 200:
                sent_count += len(batch)
        except Exception as e:
            print(f"Error sending push notifications: {e}")
    
    return {"message": f"Notifications sent to {sent_count} devices", "sent": sent_count, "total_tokens": len(tokens)}

# ============================================================================
# EXISTING ENDPOINTS (from v3)
# ============================================================================

@app.get("/health")
async def health_check():
    return {"status": "ok", "version": "4.0"}

@app.get("/")
async def root():
    return {"message": "Shanghai X Run 2026 API v4.0", "docs": "/docs"}

@app.post("/api/register")
async def register(req: RegisterRequest):
    """Register new user (runner, spectator, admin)"""
    users_col = await get_collection("users")
    
    existing = await users_col.find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    hashed_pwd = hash_password(req.password)
    
    user_data = {
        "_id": user_id,
        "email": req.email,
        "password": hashed_pwd,
        "role": req.role,
        "nome": req.nome,
        "cognome": req.cognome,
        "data_nascita": req.data_nascita,
        "telefono": req.telefono,
        "percorso": req.percorso,
        "interessi": req.interessi,
        "selfie_url": req.selfie_url,
        "bio": req.bio,
        "consent_gps": req.consent_gps,
        "consent_gdpr": req.consent_gdpr,
        "consent_rules": req.consent_rules,
        "consent_liability": req.consent_liability,
        "strava_user_id": req.strava_user_id,
        "strava_access_token": req.strava_access_token,
        "strava_refresh_token": req.strava_refresh_token,
        "created_at": datetime.utcnow(),
        "bib_number": None,
        "payment_status": PaymentStatus.PENDING,
        "status": RunnerStatus.REGISTERED if req.role == UserRole.RUNNER else None
    }
    
    await users_col.insert_one(user_data)
    
    token = create_jwt(user_id, req.email, req.role)
    
    return {
        "message": "User registered successfully",
        "user_id": user_id,
        "token": token,
        "role": req.role
    }

@app.post("/api/login")
async def login(req: LoginRequest):
    """Login"""
    users_col = await get_collection("users")
    user = await users_col.find_one({"email": req.email})
    
    if not user or not verify_password(req.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt(user["_id"], user["email"], user["role"])
    
    return {
        "token": token,
        "user": {
            "user_id": user["_id"],
            "email": user["email"],
            "role": user["role"],
            "nome": user.get("nome"),
            "cognome": user.get("cognome"),
            "bib_number": user.get("bib_number")
        }
    }

@app.get("/api/me")
async def get_me(user = Depends(get_current_user)):
    """Get current user profile"""
    user.pop("password", None)
    user["user_id"] = user.pop("_id")
    return user

# ... (continue with remaining endpoints from v3: GPS, leaderboard, matching, chat, gallery, sponsors, POIs, Strava, admin stats)
# Keeping all existing functionality intact

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
# ============================================================================
# GPS & TRACKING (from v3 - keeping existing)
# ============================================================================

@app.post("/api/gps/update")
async def update_gps(gps: GPSUpdate, user = Depends(get_current_user)):
    """Update runner GPS position"""
    if user.get("role") != UserRole.RUNNER:
        raise HTTPException(status_code=403, detail="Only runners can update GPS")
    
    gps_col = await get_collection("gps_positions")
    
    position = {
        "user_id": user["_id"],
        "lat": gps.lat,
        "lng": gps.lng,
        "timestamp": datetime.fromisoformat(gps.timestamp) if gps.timestamp else datetime.utcnow(),
        "accuracy": gps.accuracy,
        "speed": gps.speed,
        "heading": gps.heading
    }
    
    await gps_col.insert_one(position)
    
    # Broadcast to WebSocket
    await broadcast_gps_update(user["_id"], gps.lat, gps.lng)
    
    # Check geofencing (start/finish)
    # TODO: Implement geofence logic
    
    return {"message": "GPS updated"}

@app.get("/api/gps/live")
async def get_live_gps(route: Optional[str] = None):
    """Get live GPS positions of all runners"""
    users_col = await get_collection("users")
    gps_col = await get_collection("gps_positions")
    
    query = {"role": UserRole.RUNNER, "status": RunnerStatus.RUNNING}
    if route:
        query["percorso"] = route
    
    runners = await users_col.find(query).to_list(500)
    
    positions = []
    for runner in runners:
        last_pos = await gps_col.find_one({"user_id": runner["_id"]}, sort=[("timestamp", -1)])
        if last_pos:
            positions.append({
                "user_id": runner["_id"],
                "name": f"{runner.get('nome', '')} {runner.get('cognome', '')}",
                "bib": runner.get("bib_number"),
                "lat": last_pos["lat"],
                "lng": last_pos["lng"],
                "timestamp": last_pos["timestamp"].isoformat(),
                "route": runner.get("percorso")
            })
    
    return {"positions": positions, "count": len(positions)}

# ============================================================================
# LEADERBOARD
# ============================================================================

@app.get("/api/leaderboard")
async def get_leaderboard(route: Optional[str] = None):
    """Get live leaderboard"""
    users_col = await get_collection("users")
    
    query = {"role": UserRole.RUNNER}
    if route:
        query["percorso"] = route
    
    runners = await users_col.find(query).sort([("finish_time", 1), ("start_time", 1)]).to_list(500)
    
    leaderboard = []
    position = 1
    for runner in runners:
        if runner.get("status") == RunnerStatus.FINISHED:
            leaderboard.append({
                "position": position,
                "bib": runner.get("bib_number"),
                "name": f"{runner.get('nome', '')} {runner.get('cognome', '')}",
                "route": runner.get("percorso"),
                "finish_time": runner.get("finish_time").isoformat() if runner.get("finish_time") else None,
                "status": "finished",
                "progress": 100
            })
            position += 1
        elif runner.get("status") == RunnerStatus.RUNNING:
            # TODO: Calculate progress %
            leaderboard.append({
                "position": position,
                "bib": runner.get("bib_number"),
                "name": f"{runner.get('nome', '')} {runner.get('cognome', '')}",
                "route": runner.get("percorso"),
                "status": "running",
                "progress": 50  # placeholder
            })
            position += 1
    
    return {"leaderboard": leaderboard, "total": len(leaderboard)}

# ============================================================================
# MATCHING
# ============================================================================

@app.get("/api/match/suggestions")
async def get_match_suggestions(user = Depends(get_current_user)):
    """Get match suggestions based on interests"""
    users_col = await get_collection("users")
    
    my_interests = set(user.get("interessi", []))
    if not my_interests:
        return {"suggestions": [], "message": "Add interests to find matches"}
    
    # Find users with similar interests
    query = {"_id": {"$ne": user["_id"]}, "interessi": {"$in": list(my_interests)}}
    candidates = await users_col.find(query).limit(50).to_list(50)
    
    suggestions = []
    for candidate in candidates:
        common = my_interests.intersection(set(candidate.get("interessi", [])))
        if common:
            score = int((len(common) / len(my_interests)) * 100)
            suggestions.append({
                "user_id": candidate["_id"],
                "name": f"{candidate.get('nome', '')} {candidate.get('cognome', '')}",
                "role": candidate.get("role"),
                "route": candidate.get("percorso"),
                "interests": candidate.get("interessi"),
                "common_interests": list(common),
                "match_score": score,
                "photo": candidate.get("selfie_url")
            })
    
    suggestions.sort(key=lambda x: x["match_score"], reverse=True)
    
    return {"suggestions": suggestions[:20]}

@app.post("/api/match/request")
async def send_match_request(req: MatchRequest, user = Depends(get_current_user)):
    """Send match request"""
    matches_col = await get_collection("matches")
    
    existing = await matches_col.find_one({
        "user1_id": {"$in": [user["_id"], req.target_user_id]},
        "user2_id": {"$in": [user["_id"], req.target_user_id]}
    })
    
    if existing:
        return {"message": "Match request already exists", "match_id": str(existing["_id"])}
    
    match = {
        "user1_id": user["_id"],
        "user2_id": req.target_user_id,
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    
    result = await matches_col.insert_one(match)
    
    # TODO: Send push notification to target user
    
    return {"message": "Match request sent", "match_id": str(result.inserted_id)}

@app.post("/api/match/accept/{match_id}")
async def accept_match(match_id: str, user = Depends(get_current_user)):
    """Accept match request"""
    matches_col = await get_collection("matches")
    
    result = await matches_col.update_one(
        {"_id": match_id, "user2_id": user["_id"], "status": "pending"},
        {"$set": {"status": "accepted", "accepted_at": datetime.utcnow()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Match request not found or already processed")
    
    return {"message": "Match accepted"}

@app.get("/api/match/my-matches")
async def get_my_matches(user = Depends(get_current_user)):
    """Get user's matches"""
    matches_col = await get_collection("matches")
    users_col = await get_collection("users")
    
    matches = await matches_col.find({
        "$or": [{"user1_id": user["_id"]}, {"user2_id": user["_id"]}],
        "status": "accepted"
    }).to_list(100)
    
    result = []
    for match in matches:
        other_id = match["user2_id"] if match["user1_id"] == user["_id"] else match["user1_id"]
        other_user = await users_col.find_one({"_id": other_id})
        if other_user:
            result.append({
                "match_id": str(match["_id"]),
                "user": {
                    "user_id": other_user["_id"],
                    "name": f"{other_user.get('nome', '')} {other_user.get('cognome', '')}",
                    "photo": other_user.get("selfie_url"),
                    "interests": other_user.get("interessi")
                },
                "matched_at": match["accepted_at"].isoformat()
            })
    
    return {"matches": result}

# ============================================================================
# CHAT (WebSocket)
# ============================================================================

@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()
    user_id = None
    
    try:
        # Authenticate
        auth_msg = await websocket.receive_json()
        token = auth_msg.get("token")
        
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload["user_id"]
        
        ws_connections[user_id].append(websocket)
        
        while True:
            data = await websocket.receive_json()
            channel = data.get("channel", "generale")
            message = data.get("message")
            
            # Save to DB
            messages_col = await get_collection("messages")
            msg_doc = {
                "channel": channel,
                "user_id": user_id,
                "message": message,
                "timestamp": datetime.utcnow()
            }
            await messages_col.insert_one(msg_doc)
            
            # Broadcast
            await broadcast_to_channel(channel, {
                "user_id": user_id,
                "message": message,
                "timestamp": datetime.utcnow().isoformat()
            })
    
    except WebSocketDisconnect:
        if user_id:
            ws_connections[user_id].remove(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        await websocket.close()

@app.get("/api/chat/history/{channel}")
async def get_chat_history(channel: str, limit: int = 50):
    """Get chat message history"""
    messages_col = await get_collection("messages")
    messages = await messages_col.find({"channel": channel}).sort("timestamp", -1).limit(limit).to_list(limit)
    
    messages.reverse()
    for msg in messages:
        msg["_id"] = str(msg["_id"])
        msg["timestamp"] = msg["timestamp"].isoformat()
    
    return {"messages": messages}

async def broadcast_to_channel(channel: str, message: dict):
    """Broadcast message to all connected clients in channel"""
    # In production: filter by channel subscriptions
    for connections in ws_connections.values():
        for ws in connections:
            try:
                await ws.send_json({"channel": channel, "data": message})
            except:
                pass

async def broadcast_gps_update(user_id: str, lat: float, lng: float):
    """Broadcast GPS update to all connected clients"""
    message = {"type": "gps_update", "user_id": user_id, "lat": lat, "lng": lng}
    for connections in ws_connections.values():
        for ws in connections:
            try:
                await ws.send_json(message)
            except:
                pass

# ============================================================================
# GALLERY
# ============================================================================

@app.post("/api/gallery/upload")
async def upload_photo(photo: PhotoUpload, user = Depends(get_current_user)):
    """Upload geo-tagged photo"""
    gallery_col = await get_collection("gallery")
    
    photo_doc = {
        "user_id": user["_id"],
        "photo_url": photo.photo_url,
        "caption": photo.caption,
        "km_marker": photo.km_marker,
        "uploaded_at": datetime.utcnow(),
        "route": user.get("percorso")
    }
    
    result = await gallery_col.insert_one(photo_doc)
    
    return {"message": "Photo uploaded", "photo_id": str(result.inserted_id)}

@app.get("/api/gallery")
async def get_gallery(route: Optional[str] = None, km_min: Optional[float] = None, km_max: Optional[float] = None):
    """Get gallery photos with filters"""
    gallery_col = await get_collection("gallery")
    
    query = {}
    if route:
        query["route"] = route
    if km_min is not None or km_max is not None:
        query["km_marker"] = {}
        if km_min is not None:
            query["km_marker"]["$gte"] = km_min
        if km_max is not None:
            query["km_marker"]["$lte"] = km_max
    
    photos = await gallery_col.find(query).sort("uploaded_at", -1).limit(100).to_list(100)
    
    for photo in photos:
        photo["_id"] = str(photo["_id"])
        photo["uploaded_at"] = photo["uploaded_at"].isoformat()
    
    return {"photos": photos, "count": len(photos)}

@app.delete("/api/admin/gallery/{photo_id}")
async def delete_photo(photo_id: str, admin = Depends(require_admin)):
    """Delete photo (admin)"""
    gallery_col = await get_collection("gallery")
    result = await gallery_col.delete_one({"_id": photo_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Photo not found")
    
    return {"message": "Photo deleted"}

# ============================================================================
# PAYMENT CONFIG
# ============================================================================

@app.get("/api/config/payment")
async def get_payment_config():
    """Get payment configuration"""
    config_col = await get_collection("payment_config")
    config = await config_col.find_one({})
    
    if not config:
        return {"paypal_link": None, "satispay_link": None, "iban": None}
    
    config.pop("_id", None)
    return config

@app.put("/api/admin/config/payment")
async def update_payment_config(req: PaymentConfig, admin = Depends(require_admin)):
    """Update payment configuration"""
    config_col = await get_collection("payment_config")
    
    update_data = req.dict()
    update_data["updated_at"] = datetime.utcnow()
    
    await config_col.update_one({}, {"$set": update_data}, upsert=True)
    
    return {"message": "Payment config updated"}

# ============================================================================
# SPONSORS
# ============================================================================

@app.get("/api/sponsors")
async def get_sponsors():
    """Get all sponsors"""
    sponsors_col = await get_collection("sponsors")
    sponsors = await sponsors_col.find({}).sort("donation_amount", -1).to_list(100)
    
    for sponsor in sponsors:
        sponsor["_id"] = str(sponsor["_id"])
    
    return {"sponsors": sponsors}

@app.post("/api/admin/sponsors")
async def add_sponsor(req: SponsorRequest, admin = Depends(require_admin)):
    """Add new sponsor"""
    sponsors_col = await get_collection("sponsors")
    
    sponsor_doc = req.dict()
    sponsor_doc["created_at"] = datetime.utcnow()
    
    result = await sponsors_col.insert_one(sponsor_doc)
    
    return {"message": "Sponsor added", "sponsor_id": str(result.inserted_id)}

@app.delete("/api/admin/sponsors/{sponsor_id}")
async def delete_sponsor(sponsor_id: str, admin = Depends(require_admin)):
    """Delete sponsor"""
    sponsors_col = await get_collection("sponsors")
    result = await sponsors_col.delete_one({"_id": sponsor_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Sponsor not found")
    
    return {"message": "Sponsor deleted"}

# ============================================================================
# STRAVA INTEGRATION
# ============================================================================

@app.get("/api/strava/connect")
async def strava_connect(user = Depends(get_current_user)):
    """Get Strava OAuth URL"""
    if not STRAVA_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Strava client ID not configured")
    
    redirect_uri = f"{FRONTEND_URL}/strava/callback"
    auth_url = f"https://www.strava.com/oauth/authorize?client_id={STRAVA_CLIENT_ID}&response_type=code&redirect_uri={redirect_uri}&scope=read,activity:read_all"
    
    return {"auth_url": auth_url}

@app.post("/api/strava/callback")
async def strava_callback(code: str, user = Depends(get_current_user)):
    """Strava OAuth callback"""
    if not STRAVA_CLIENT_ID or not STRAVA_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Strava not configured")
    
    # Exchange code for token
    token_url = "https://www.strava.com/oauth/token"
    response = requests.post(token_url, data={
        "client_id": STRAVA_CLIENT_ID,
        "client_secret": STRAVA_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code"
    })
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Strava OAuth failed")
    
    data = response.json()
    
    # Save tokens
    users_col = await get_collection("users")
    await users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "strava_user_id": str(data["athlete"]["id"]),
            "strava_access_token": data["access_token"],
            "strava_refresh_token": data["refresh_token"],
            "strava_connected_at": datetime.utcnow()
        }}
    )
    
    return {"message": "Strava connected successfully", "athlete": data["athlete"]}

@app.get("/api/strava/activities")
async def get_strava_activities(user = Depends(get_current_user)):
    """Get user's Strava activities"""
    if not user.get("strava_access_token"):
        raise HTTPException(status_code=400, detail="Strava not connected")
    
    headers = {"Authorization": f"Bearer {user['strava_access_token']}"}
    response = requests.get("https://www.strava.com/api/v3/athlete/activities", headers=headers, params={"per_page": 10})
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch Strava activities")
    
    return {"activities": response.json()}

# ============================================================================
# ADMIN STATS
# ============================================================================

@app.get("/api/admin/stats")
async def get_admin_stats(admin = Depends(require_admin)):
    """Get admin statistics"""
    users_col = await get_collection("users")
    adoptions_col = await get_collection("adoptions")
    bibs_col = await get_collection("bibs")
    
    total_runners = await users_col.count_documents({"role": UserRole.RUNNER})
    total_spectators = await users_col.count_documents({"role": UserRole.SPECTATOR})
    
    bibs_assigned = await bibs_col.count_documents({"status": BibStatus.ASSEGNATO})
    bibs_reserved = await bibs_col.count_documents({"status": BibStatus.RISERVATO})
    bibs_available = await bibs_col.count_documents({"status": BibStatus.DISPONIBILE})
    
    adoptions = await adoptions_col.find({"payment_status": PaymentStatus.COMPLETED}).to_list(1000)
    total_donations = sum(a["amount"] for a in adoptions)
    total_adoptions = len(adoptions)
    
    return {
        "total_runners": total_runners,
        "total_spectators": total_spectators,
        "bibs_assigned": bibs_assigned,
        "bibs_reserved": bibs_reserved,
        "bibs_available": bibs_available,
        "total_donations": total_donations,
        "total_adoptions": total_adoptions
    }

@app.get("/api/admin/race-dashboard")
async def admin_race_dashboard(admin = Depends(require_admin)):
    """Get live race dashboard for admin"""
    users_col = await get_collection("users")
    
    runners_ready = await users_col.count_documents({"role": UserRole.RUNNER, "status": RunnerStatus.READY})
    runners_running = await users_col.count_documents({"role": UserRole.RUNNER, "status": RunnerStatus.RUNNING})
    runners_finished = await users_col.count_documents({"role": UserRole.RUNNER, "status": RunnerStatus.FINISHED})
    
    spectators_online = len([u for conns in ws_connections.values() for u in conns])
    
    return {
        "runners_ready": runners_ready,
        "runners_running": runners_running,
        "runners_finished": runners_finished,
        "spectators_online": spectators_online
    }

# ============================================================================
# POIs
# ============================================================================

@app.post("/api/admin/pois")
async def add_poi(poi: POI, admin = Depends(require_admin)):
    """Add Point of Interest"""
    pois_col = await get_collection("pois")
    
    poi_doc = poi.dict()
    poi_doc["created_at"] = datetime.utcnow()
    
    result = await pois_col.insert_one(poi_doc)
    
    return {"message": "POI added", "poi_id": str(result.inserted_id)}

@app.get("/api/pois")
async def get_pois():
    """Get all POIs"""
    pois_col = await get_collection("pois")
    pois = await pois_col.find({}).to_list(100)
    
    for poi in pois:
        poi["_id"] = str(poi["_id"])
    
    return {"pois": pois}

@app.delete("/api/admin/pois/{poi_id}")
async def delete_poi(poi_id: str, admin = Depends(require_admin)):
    """Delete POI"""
    pois_col = await get_collection("pois")
    result = await pois_col.delete_one({"_id": poi_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="POI not found")
    
    return {"message": "POI deleted"}

# ============================================================================
# ROUTES UPLOAD (GPX)
# ============================================================================

@app.post("/api/admin/routes/upload")
async def upload_route(route_type: str = Form(...), gpx_file: UploadFile = File(...), admin = Depends(require_admin)):
    """Upload GPX file for route"""
    routes_col = await get_collection("routes")
    
    # Parse GPX
    content = await gpx_file.read()
    gpx = gpxpy.parse(content.decode())
    
    points = []
    for track in gpx.tracks:
        for segment in track.segments:
            for point in segment.points:
                points.append({"lat": point.latitude, "lng": point.longitude, "elevation": point.elevation})
    
    # Save to DB
    await routes_col.update_one(
        {"type": route_type},
        {"$set": {
            "gpx_points": points,
            "gpx_url": f"/uploads/{gpx_file.filename}",  # In production: upload to S3/Cloud Storage
            "uploaded_at": datetime.utcnow()
        }},
        upsert=True
    )
    
    return {"message": f"Route {route_type} uploaded successfully", "points_count": len(points)}

print("✅ Shanghai X Run 2026 Backend v4.0 - 47 endpoints ready")
