import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret")


def generate_token(user_id, expires_hours=2):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=expires_hours)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header:
            return jsonify({"msg": "Missing token"}), 401

        parts = auth_header.split()
        if len(parts) != 2:
            return jsonify({"msg": "Invalid Authorization header"}), 401

        token = parts[1]
        user_id = verify_token(token)

        if not user_id:
            return jsonify({"msg": "Invalid or expired token"}), 401

        return f(user_id, *args, **kwargs)
    return decorated
