import {
  FormEvent,
  useState,
} from "react";

import {
  Link,
  useNavigate,
} from "react-router-dom";

import { auth } from "../services/auth";


export default function Login() {

  const [email, setEmail] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [error, setError] =
    useState("");

  const nav = useNavigate();


  async function submit(
    e: FormEvent
  ) {

    e.preventDefault();

    setError("");

    try {

      await auth.login(
        email,
        password
      );

      nav("/");

    } catch (e) {

      setError(
        e instanceof Error
          ? e.message
          : "Login failed"
      );
    }
  }


  return (
    <div className="min-h-screen grid place-items-center px-4">

      <form
        onSubmit={submit}
        className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4"
      >

        <div>

          <h1 className="text-xl font-semibold">
            SOC Agent Login
          </h1>

          <p className="text-sm text-slate-400">
            Sign in with your email and password.
          </p>

        </div>


        {error && (
          <div className="text-sm text-red-400">
            {error}
          </div>
        )}


        <input
          className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2"
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) =>
            setEmail(e.target.value)
          }
          required
        />


        <input
          className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) =>
            setPassword(e.target.value)
          }
          required
        />


        <div className="text-right">

          <Link
            className="text-sm text-blue-400 hover:text-blue-300"
            to="/forgot-password"
          >
            Forgot password?
          </Link>

        </div>


        <button
          type="submit"
          className="w-full bg-blue-600 hover:bg-blue-500 rounded px-3 py-2 font-medium"
        >
          Login
        </button>


        <p className="text-sm text-slate-400">

          New user?{" "}

          <Link
            className="text-blue-400"
            to="/register"
          >
            Create account
          </Link>

        </p>

      </form>

    </div>
  );
}