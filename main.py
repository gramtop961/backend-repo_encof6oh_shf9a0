import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import create_document, get_documents, db

# Environment / Auth Config
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkeychange")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Video Editing Agency API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Models ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ContactIn(BaseModel):
    name: str
    email: EmailStr
    message: str

class Testimonial(BaseModel):
    name: str
    role: str
    quote: str
    avatar: Optional[str] = None

class PricingTier(BaseModel):
    name: str
    price: float
    description: str
    features: list[str]

class AuthIn(BaseModel):
    email: EmailStr
    password: str


# ---------- Auth Utilities ----------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    users = get_documents("agencyuser", {"email": email}, limit=1)
    if not users:
        raise credentials_exception
    return users[0]


# ---------- Routes ----------
@app.get("/")
def root():
    return {"status": "ok", "service": "Video Editing Agency API"}


@app.get("/pricing", response_model=list[PricingTier])
def get_pricing():
    return [
        PricingTier(
            name="Starter",
            price=299,
            description="Perfect for quick social edits",
            features=["Up to 60s video", "1 revision", "48h delivery"],
        ),
        PricingTier(
            name="Pro",
            price=699,
            description="For creators and brands",
            features=["Up to 5 min", "3 revisions", "Color + sound mix"],
        ),
        PricingTier(
            name="Studio",
            price=1499,
            description="Agency-level polish",
            features=["10+ min", "Unlimited revisions", "Motion graphics"],
        ),
    ]


@app.get("/testimonials", response_model=list[Testimonial])
def get_testimonials():
    return [
        Testimonial(name="Ava Stone", role="Creator", quote="They made my content pop — fast and flawless!"),
        Testimonial(name="Liam Chen", role="Brand Manager", quote="Consistent quality and on-time delivery every time."),
        Testimonial(name="Maya Patel", role="Founder", quote="Our ads converted 2x better after their edits."),
    ]


@app.post("/contact")
def contact(message: ContactIn):
    try:
        create_document("contactmessage", message.model_dump())
        return {"ok": True, "received": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---- Auth ----
@app.post("/auth/register")
def register(payload: AuthIn):
    email = payload.email
    password = payload.password
    existing = get_documents("agencyuser", {"email": email}, limit=1)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = get_password_hash(password)
    create_document("agencyuser", {"email": email, "password_hash": password_hash, "name": email.split("@")[0]})
    access_token = create_access_token({"sub": email})
    return Token(access_token=access_token)


@app.post("/auth/login")
def login(payload: AuthIn):
    email = payload.email
    password = payload.password
    user = get_documents("agencyuser", {"email": email}, limit=1)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    user = user[0]
    if not verify_password(password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token({"sub": email})
    return Token(access_token=access_token)


@app.get("/me")
def me(current_user: dict = Depends(get_current_user)):
    return {"email": current_user.get("email"), "name": current_user.get("name")}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
