from __future__ import annotations

import smtplib
from email.message import EmailMessage

from app.config.settings import settings

def send_password_reset_otp(
    recipient_email: str,
    otp: str,
) -> None:
    """
    Send a password-reset OTP through Gmail SMTP.
    """

    if not settings.smtp_configured:
        raise RuntimeError(
            "SMTP email configuration is missing."
        )

    message = EmailMessage()

    message["Subject"] = "SOC Agent - Password Reset Code"
    message["From"] = settings.smtp_from_email
    message["To"] = recipient_email

    message.set_content(
        f"""
SOC Investigation Agent

We received a request to reset your password.

Your verification code is:

{otp}

This code expires in 10 minutes.

If you did not request a password reset, you can ignore this email.

Do not share this verification code with anyone.
""".strip()
    )

    try:
        with smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=15,
        ) as server:

            server.ehlo()
            server.starttls()
            server.ehlo()

            server.login(
                settings.smtp_username,
                settings.smtp_password,
            )

            server.send_message(message)

    except Exception as exc:
        raise RuntimeError(
            f"Unable to send password reset email: {exc}"
        ) from exc