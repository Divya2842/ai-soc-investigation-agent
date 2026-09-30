const TOKEN_KEY = "soc_access_token";

export type AuthUser = {
  id: number;
  email: string;
  full_name?: string | null;
  is_active: boolean;
};

export const auth = {
  token: () => localStorage.getItem(TOKEN_KEY),

  setToken: (token: string) =>
    localStorage.setItem(TOKEN_KEY, token),

  logout: () =>
    localStorage.removeItem(TOKEN_KEY),

  async login(
    email: string,
    password: string
  ) {
    const r = await fetch(
      "/api/auth/login",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          password,
        }),
      }
    );

    if (!r.ok) {
      const error = await r
        .json()
        .catch(() => ({}));

      throw new Error(
        error.detail ||
        "Login failed"
      );
    }

    const data = await r.json();

    this.setToken(
      data.access_token
    );

    return data;
  },

  async register(
    email: string,
    password: string,
    full_name?: string
  ) {
    const r = await fetch(
      "/api/auth/register",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify({
          email,
          password,
          full_name:
            full_name || null,
        }),
      }
    );

    if (!r.ok) {
      const error = await r
        .json()
        .catch(() => ({}));

      throw new Error(
        error.detail ||
        "Registration failed"
      );
    }

    return await r.json();
  },
};