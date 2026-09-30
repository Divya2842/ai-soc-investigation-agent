from __future__ import annotations
import base64, hashlib, hmac, json, os, time
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config.settings import settings
from app.database.session import get_db
from app.models.user import User

bearer = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        _, rounds, salt64, expected64 = encoded.split("$", 3)
        salt = base64.urlsafe_b64decode(salt64)
        expected = base64.urlsafe_b64decode(expected64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

def create_access_token(user: User) -> str:
    now = int(time.time())
    header = _b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",",":")).encode())
    payload = _b64(json.dumps({"sub":str(user.id),"username":user.username,"iat":now,"exp":now + settings.jwt_expire_minutes * 60}, separators=(",",":")).encode())
    signing = f"{header}.{payload}".encode()
    signature = _b64(hmac.new(settings.jwt_secret_key.encode(), signing, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"

def decode_access_token(token: str) -> dict:
    try:
        header, payload, signature = token.split(".")
        signing = f"{header}.{payload}".encode()
        expected = _b64(hmac.new(settings.jwt_secret_key.encode(), signing, hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected): raise ValueError()
        data = json.loads(_unb64(payload))
        if int(data.get("exp", 0)) < int(time.time()): raise ValueError()
        return data
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token", headers={"WWW-Authenticate":"Bearer"})

def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate":"Bearer"})
    data = decode_access_token(credentials.credentials)
    user = db.scalar(select(User).where(User.id == int(data["sub"])))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User is unavailable")
    return user
