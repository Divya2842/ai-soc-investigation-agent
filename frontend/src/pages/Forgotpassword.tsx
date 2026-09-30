import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

type Step = "email" | "otp" | "password";

export default function ForgotPassword() {
  const [step, setStep] = useState<Step>("email");

  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();

  async function requestOTP(e: FormEvent) {
    e.preventDefault();

    setError("");
    setMessage("");
    setLoading(true);

    try {
      const response = await fetch(
        "/api/auth/forgot-password",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Unable to request verification code"
        );
      }

      setMessage(
        "If an account exists for this email, a verification code has been sent."
      );

      setStep("otp");

    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to request verification code"
      );

    } finally {
      setLoading(false);
    }
  }


  async function verifyOTP(e: FormEvent) {
    e.preventDefault();

    setError("");
    setMessage("");
    setLoading(true);

    try {
      const response = await fetch(
        "/api/auth/verify-reset-otp",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
            otp,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Verification failed"
        );
      }

      setMessage(
        "Verification successful. Enter your new password."
      );

      setStep("password");

    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Verification failed"
      );

    } finally {
      setLoading(false);
    }
  }


  async function resetPassword(e: FormEvent) {
    e.preventDefault();

    setError("");
    setMessage("");

    if (newPassword !== confirmPassword) {
      setError(
        "Passwords do not match."
      );
      return;
    }

    if (newPassword.length < 8) {
      setError(
        "Password must contain at least 8 characters."
      );
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(
        "/api/auth/reset-password",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
            otp,
            new_password: newPassword,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Password reset failed"
        );
      }

      setMessage(
        "Password reset successfully. Redirecting to login..."
      );

      setTimeout(() => {
        navigate("/login");
      }, 1500);

    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Password reset failed"
      );

    } finally {
      setLoading(false);
    }
  }


  return (
    <div className="min-h-screen grid place-items-center px-4">

      <div className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-xl p-6">

        {step === "email" && (
          <form
            onSubmit={requestOTP}
            className="space-y-4"
          >

            <div>
              <h1 className="text-xl font-semibold">
                Forgot Password
              </h1>

              <p className="text-sm text-slate-400 mt-1">
                Enter your registered email address.
              </p>
            </div>

            {error && (
              <div className="text-sm text-red-400">
                {error}
              </div>
            )}

            {message && (
              <div className="text-sm text-green-400">
                {message}
              </div>
            )}

            <input
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2"
              type="email"
              placeholder="Email address"
              value={email}
              onChange={(e) =>
                setEmail(e.target.value)
              }
              required
            />

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded px-3 py-2 font-medium"
            >
              {loading
                ? "Sending..."
                : "Send verification code"}
            </button>

          </form>
        )}


        {step === "otp" && (
          <form
            onSubmit={verifyOTP}
            className="space-y-4"
          >

            <div>
              <h1 className="text-xl font-semibold">
                Verify Code
              </h1>

              <p className="text-sm text-slate-400 mt-1">
                Enter the 6-digit verification code.
              </p>
            </div>

            {error && (
              <div className="text-sm text-red-400">
                {error}
              </div>
            )}

            {message && (
              <div className="text-sm text-green-400">
                {message}
              </div>
            )}

            <input
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-center tracking-widest"
              type="text"
              inputMode="numeric"
              placeholder="000000"
              value={otp}
              maxLength={6}
              onChange={(e) => {
                const value =
                  e.target.value.replace(
                    /\D/g,
                    ""
                  );

                setOtp(value);
              }}
              required
            />

            <button
              type="submit"
              disabled={
                loading ||
                otp.length !== 6
              }
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded px-3 py-2 font-medium"
            >
              {loading
                ? "Verifying..."
                : "Verify code"}
            </button>

            <button
              type="button"
              onClick={() => {
                setStep("email");
                setOtp("");
                setError("");
                setMessage("");
              }}
              className="w-full text-sm text-blue-400"
            >
              Request another code
            </button>

          </form>
        )}


        {step === "password" && (
          <form
            onSubmit={resetPassword}
            className="space-y-4"
          >

            <div>
              <h1 className="text-xl font-semibold">
                Reset Password
              </h1>

              <p className="text-sm text-slate-400 mt-1">
                Create a new password for your account.
              </p>
            </div>

            {error && (
              <div className="text-sm text-red-400">
                {error}
              </div>
            )}

            {message && (
              <div className="text-sm text-green-400">
                {message}
              </div>
            )}

            <input
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2"
              type="password"
              placeholder="New password"
              value={newPassword}
              onChange={(e) =>
                setNewPassword(
                  e.target.value
                )
              }
              minLength={8}
              required
            />

            <input
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2"
              type="password"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) =>
                setConfirmPassword(
                  e.target.value
                )
              }
              minLength={8}
              required
            />

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded px-3 py-2 font-medium"
            >
              {loading
                ? "Resetting..."
                : "Reset Password"}
            </button>

          </form>
        )}


        <p className="text-sm text-slate-400 mt-4">
          Remember your password?{" "}
          <Link
            className="text-blue-400"
            to="/login"
          >
            Back to login
          </Link>
        </p>

      </div>
    </div>
  );
}