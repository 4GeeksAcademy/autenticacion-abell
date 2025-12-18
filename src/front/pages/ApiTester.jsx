import React, { useState } from "react";

const ApiTester = () => {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [token, setToken] = useState("");
    const [response, setResponse] = useState("");

    const login = async () => {
        const res = await fetch("http://localhost:3001/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        setResponse(JSON.stringify(data, null, 2));
        if (data.token) setToken(data.token);
    };

    const privateRequest = async () => {
        const res = await fetch("http://localhost:3001/private", {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });
        const data = await res.json();
        setResponse(JSON.stringify(data, null, 2));
    };

    return (
        <div className="container mt-5">
            <h2>API Tester</h2>

            <input
                className="form-control mb-2"
                placeholder="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
            />

            <input
                className="form-control mb-2"
                type="password"
                placeholder="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
            />

            <button className="btn btn-primary me-2" onClick={login}>
                Login
            </button>

            <button className="btn btn-success" onClick={privateRequest}>
                Private endpoint
            </button>

            <hr />

            <h5>Token</h5>
            <textarea className="form-control" rows="4" value={token} readOnly />

            <h5 className="mt-3">Response</h5>
            <pre className="bg-light p-3">{response}</pre>
        </div>
    );
};

export default ApiTester;
import React, { useState } from "react";
