import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import "./index.css";

import App from "./App";
import Dashboard from "./pages/Dashboard";
import AlertsList from "./pages/AlertsList";
import AlertDetail from "./pages/AlertDetail";
import IocLookup from "./pages/IocLookup";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/Forgotpassword";
import RequireAuth from "./components/RequireAuth";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>

        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/forgot-password"
          element={<ForgotPassword />}
        />

        {/* Protected routes */}
        <Route element={<RequireAuth />}>
          <Route path="/" element={<App />}>
            <Route index element={<Dashboard />} />
            <Route path="alerts" element={<AlertsList />} />
            <Route path="alerts/:id" element={<AlertDetail />} />
            <Route path="iocs" element={<IocLookup />} />
          </Route>
        </Route>

      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);