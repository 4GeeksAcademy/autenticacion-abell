


import React from "react";
import image from "../assets/img/image.png";

export default function Private() {
    const token = sessionStorage.getItem("token");
    if (!token) {
        return <h2>No autorizado</h2>;
    }
    return (
        <div style={{
            backgroundImage: `url(${image})`,
            backgroundSize: "cover",
            backgroundPosition: "center",
            width: "100vw",
            height: "100vh",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            flexDirection: "column",
            color: "white",
            fontSize: "3rem",
            fontWeight: "bold",
            textShadow: "2px 2px 8px black"
        }}>
            Bienvenido Nakama!
        </div>
    );
}

