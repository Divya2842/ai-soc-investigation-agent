from __future__ import annotations

import os

import resend


def send_password_reset_otp(
    recipient_email: str,
    otp: str,
) -> None:
    """
    Send a password-reset OTP using the Resend HTTPS API.
    """

    api_key = os.getenv("RESEND_API_KEY")

    if not api_key:
        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    resend.api_key = api_key

    try:
        resend.Emails.send(
            {
                "from": "SOC Investigation Agent <onboarding@resend.dev>",
                "to": [recipient_email],
                "subject": "SOC Agent - Password Reset Code",
                "text": f"""
SOC Investigation Agent

We received a request to reset your password.

Your verification code is:

{otp}

This code expires in 10 minutes.

If you did not request a password reset, you can ignore this email.

Do not share this verification code with anyone.
""".strip(),
            }
        )

    except Exception as exc:
        raise RuntimeError(
            f"Unable to send password reset email: {exc}"
        ) from exc