import { Navigate, Outlet } from "react-router-dom";
import { auth } from "../services/auth";
export default function RequireAuth(){ return auth.token() ? <Outlet/> : <Navigate to="/login" replace/>; }
