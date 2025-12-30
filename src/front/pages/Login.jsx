import { useState } from "react";
import { useNavigate } from "react-router-dom";
import homeImg from "../assets/img/home.webp";
function Login() {
    const navigate = useNavigate();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");

    const [showHome, setShowHome] = useState(false);
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");
        try {
            const BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:3001';
            const res = await fetch(`${BASE}/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
                mode: "cors",
                credentials: "include"
            });
            const data = await res.json();
            if (!res.ok) {
                setError(data.msg || "Credenciales incorrectas");
                return;
            }
            sessionStorage.setItem("token", data.token);
            setShowHome(true);
        } catch (err) {
            setError("No se pudo conectar con el servidor");
        }
    };

    return (
        showHome ? (
            <div style={{ height: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", background: "#fff" }}>
                <h1 style={{ color: "#8000ff", fontWeight: 700, marginBottom: "2rem", fontSize: "2.5rem", textShadow: "0 2px 8px rgba(0,0,0,0.12)" }}>Bienvenido Nakama!</h1>
                <img src={homeImg} alt="Home" style={{ maxWidth: "80vw", maxHeight: "80vh", borderRadius: "16px", boxShadow: "0 4px 24px rgba(0,0,0,0.2)" }} />
            </div>
        ) : (
            <div className="container mt-5" style={{ maxWidth: 400 }}>
                <h2 className="mb-3">Iniciar sesión</h2>
                <form onSubmit={handleSubmit}>
                    <input
                        className="form-control mb-2"
                        type="email"
                        placeholder="Email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                    />
                    <input
                        className="form-control mb-3"
                        type="password"
                        placeholder="Contraseña"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                    />
                    {error && <div className="alert alert-danger">{error}</div>}
                    <button className="btn btn-primary w-100">Entrar</button>
                </form>
            </div>
        )
    );
}
export default Login;
