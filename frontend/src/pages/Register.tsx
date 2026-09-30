import {
  FormEvent,
  useState,
} from "react";

import {
  Link,
  useNavigate,
} from "react-router-dom";

import { auth } from "../services/auth";


export default function Register() {

  const [name, setName] =
    useState("");

  const [email, setEmail] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState("");

  const [error, setError] =
    useState("");

  const nav = useNavigate();


  async function submit(
    e: FormEvent
  ) {

    e.preventDefault();

    setError("");

    if (
      password !==
      confirmPassword
    ) {
      setError(
        "Passwords do not match"
      );

      return;
    }

    try {

      await auth.register(
        email,
        password,
        name
      );

      nav("/login");

    } catch (e) {

      setError(
        e instanceof Error
          ? e.message
          : "Registration failed"
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
            Create SOC User
          </h1>

          <p className="text-sm text-slate-400">
            Create your SOC Agent account.
          </p>

        </div>


        {error && (
          <div className="text-sm text-red-400">
            {error}
          </div>
        )}


        <input
          className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2"
          placeholder="Full name (optional)"
          value={name}
          onChange={(e) =>
            setName(e.target.value)
          }
        />


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
          placeholder="Password (min 8 characters)"
          value={password}
          onChange={(e) =>
            setPassword(e.target.value)
          }
          minLength={8}
          required
        />


        <input
          className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2"
          type="password"
          placeholder="Confirm password"
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
          className="w-full bg-blue-600 hover:bg-blue-500 rounded px-3 py-2 font-medium"
        >
          Create account
        </button>


        <p className="text-sm text-slate-400">

          Already registered?{" "}

          <Link
            className="text-blue-400"
            to="/login"
          >
            Login
          </Link>

        </p>

      </form>

    </div>
  );
}