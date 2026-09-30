from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.password_reset import PasswordResetOTP
from app.models.user import User
from app.security.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.services.emailservice import send_password_reset_otp


router = APIRouter(
    prefix="/api/auth",
    tags=["auth"],
)

OTP_EXPIRY_MINUTES = 10
MAX_OTP_ATTEMPTS = 5


# =========================================================
# REQUEST MODELS
# =========================================================

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=160)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str = Field(min_length=6, max_length=6)


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=8, max_length=128)


# =========================================================
# HELPERS
# =========================================================

def normalize_email(email: str) -> str:
    return email.strip().lower()


def public_user(user: User):
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
    }


def generate_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp: str) -> str:
    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


def otp_matches(
    supplied_otp: str,
    stored_hash: str,
) -> bool:

    supplied_hash = hash_otp(
        supplied_otp
    )

    return hmac.compare_digest(
        supplied_hash,
        stored_hash,
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_aware(value: datetime) -> datetime:

    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value


def get_latest_otp(
    db: Session,
    email: str,
) -> PasswordResetOTP | None:

    return db.scalar(
        select(PasswordResetOTP)
        .where(
            PasswordResetOTP.email == email
        )
        .order_by(
            PasswordResetOTP.created_at.desc()
        )
    )


# =========================================================
# REGISTER
# =========================================================

@router.post(
    "/register",
    status_code=201,
)
def register(
    body: RegisterRequest,
    db: Session = Depends(get_db),
):

    email = normalize_email(
        str(body.email)
    )

    # Email is now the unique account identifier.
    existing = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        )

    try:
        password_hash = hash_password(
            body.password
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    # Keep username internally because the existing
    # PostgreSQL column is NOT NULL.
    # Users never need to enter or remember it.
    user = User(
        username=email,
        email=email,
        full_name=body.full_name,
        password_hash=password_hash,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Account created successfully",
        "user": public_user(user),
    }


# =========================================================
# LOGIN
# =========================================================

@router.post("/login")
def login(
    body: LoginRequest,
    db: Session = Depends(get_db),
):

    email = normalize_email(
        str(body.email)
    )

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    if (
        not user
        or not verify_password(
            body.password,
            user.password_hash,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is inactive",
        )

    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "user": public_user(user),
    }


# =========================================================
# FORGOT PASSWORD
# =========================================================

@router.post("/forgot-password")
def forgot_password(
    body: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):

    email = normalize_email(
        str(body.email)
    )

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    # Don't reveal whether an account exists.
    if not user:
        return {
            "message": (
                "If an account exists for this email, "
                "a verification code has been sent."
            )
        }

    # Delete previous OTPs.
    db.execute(
        delete(PasswordResetOTP).where(
            PasswordResetOTP.email == email
        )
    )

    otp = generate_otp()

    otp_record = PasswordResetOTP(
        email=email,
        otp_hash=hash_otp(otp),
        expires_at=(
            utc_now()
            + timedelta(
                minutes=OTP_EXPIRY_MINUTES
            )
        ),
        attempts=0,
    )

    db.add(otp_record)
    db.commit()

    # Send OTP through Gmail.
    try:
        send_password_reset_otp(
            recipient_email=email,
            otp=otp,
        )

    except Exception as exc:

        print(
            f"PASSWORD RESET EMAIL ERROR: {exc}",
            flush=True,
        )

        db.delete(otp_record)
        db.commit()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to send verification code. "
                "Please try again."
            ),
        )

    return {
        "message": (
            "If an account exists for this email, "
            "a verification code has been sent."
        )
    }


# =========================================================
# VERIFY RESET OTP
# =========================================================

@router.post("/verify-reset-otp")
def verify_reset_otp(
    body: VerifyOTPRequest,
    db: Session = Depends(get_db),
):

    email = normalize_email(
        str(body.email)
    )

    record = get_latest_otp(
        db,
        email,
    )

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification code",
        )

    expires_at = make_aware(
        record.expires_at
    )

    if utc_now() > expires_at:

        db.delete(record)
        db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification code",
        )

    if record.attempts >= MAX_OTP_ATTEMPTS:

        db.delete(record)
        db.commit()

        raise HTTPException(
            status_code=400,
            detail=(
                "Too many incorrect attempts. "
                "Request a new code."
            ),
        )

    if not otp_matches(
        body.otp,
        record.otp_hash,
    ):

        record.attempts += 1
        db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification code",
        )

    return {
        "message": "Verification code confirmed."
    }


# =========================================================
# RESET PASSWORD
# =========================================================

@router.post("/reset-password")
def reset_password(
    body: ResetPasswordRequest,
    db: Session = Depends(get_db),
):

    email = normalize_email(
        str(body.email)
    )

    record = get_latest_otp(
        db,
        email,
    )

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification code",
        )

    expires_at = make_aware(
        record.expires_at
    )

    if utc_now() > expires_at:

        db.delete(record)
        db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification code",
        )

    if record.attempts >= MAX_OTP_ATTEMPTS:

        db.delete(record)
        db.commit()

        raise HTTPException(
            status_code=400,
            detail=(
                "Too many incorrect attempts. "
                "Request a new code."
            ),
        )

    if not otp_matches(
        body.otp,
        record.otp_hash,
    ):

        record.attempts += 1
        db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification code",
        )

    user = db.scalar(
        select(User).where(
            User.email == email
        )
    )

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Unable to reset password",
        )

    try:
        user.password_hash = hash_password(
            body.new_password
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    # OTP cannot be reused.
    db.execute(
        delete(PasswordResetOTP).where(
            PasswordResetOTP.email == email
        )
    )

    db.commit()

    return {
        "message": "Password reset successfully."
    }


# =========================================================
# CURRENT USER
# =========================================================

@router.get("/me")
def me(
    user: User = Depends(get_current_user),
):
    return public_user(user)