 
from flask import Flask, request, jsonify, url_for, Blueprint, redirect
from flasgger import swag_from
import jwt
import os
from api.models import db, User
from api.utils import generate_sitemap, APIException
from api.auth import jwt_required
from werkzeug.security import generate_password_hash, check_password_hash

api = Blueprint('api', __name__)

@api.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"msg": "Faltan campos obligatorios"}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "Credenciales inválidas"}), 401
    from api.auth import generate_token
    token = generate_token(user.id)
    return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "first_name": user.first_name, "last_name": user.last_name}}), 200
"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint, redirect
import jwt
import os
from api.models import db, User
from api.utils import generate_sitemap, APIException
from api.auth import jwt_required
from werkzeug.security import generate_password_hash
@api.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    if not email or not password or not first_name or not last_name:
        return jsonify({"msg": "Faltan campos obligatorios"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "El email ya está registrado"}), 400
    hashed_password = generate_password_hash(password)
    user = User(email=email, password=hashed_password, first_name=first_name, last_name=last_name, is_active=True)
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "Usuario registrado exitosamente"}), 201

from flask_cors import CORS

api = Blueprint('api', __name__)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route('/users', methods=['GET'])
@jwt_required
@swag_from({
    'tags': ['Usuarios'],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer <token>'
        }
    ],
    'responses': {
        200: {'description': 'Lista de usuarios'},
        401: {'description': 'Token requerido o inválido'}
    }
})
def list_users(auth_user_id):
    users = User.query.all()
    data = [
        {
            'id': u.id,
            'email': u.email,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'is_active': bool(u.is_active)
        }
        for u in users
    ]
    return jsonify(data), 200


@api.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required
@swag_from({
    'tags': ['Usuarios'],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer <token>'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'email': {'type': 'string'},
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'Usuario actualizado'},
        404: {'description': 'Usuario no encontrado'},
        401: {'description': 'Token requerido o inválido'}
    }
})
def update_user(auth_user_id, user_id):
    data = request.get_json() or {}
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "Usuario no encontrado"}), 404
    user.email = data.get('email', user.email)
    if 'first_name' in data:
        user.first_name = data.get('first_name')
    if 'last_name' in data:
        user.last_name = data.get('last_name')
    db.session.commit()
    return jsonify({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_active': bool(user.is_active)
    }), 200


@api.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required
@swag_from({
    'tags': ['Usuarios'],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer <token>'
        }
    ],
    'responses': {
        200: {'description': 'Usuario eliminado'},
        404: {'description': 'Usuario no encontrado'},
        401: {'description': 'Token requerido o inválido'}
    }
})
def delete_user(auth_user_id, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "Usuario no encontrado"}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({"msg": "Usuario eliminado"}), 200


@api.route('/dev-tools', methods=['GET'])
def dev_tools():
    return redirect(url_for('static', filename='dev-tools.html'))


@api.route('/private', methods=['GET'])
def private_route():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"msg": "Token requerido"}), 401

    try:
        token = auth_header.split(' ')[1]
        secret = os.getenv('JWT_SECRET_KEY') or os.getenv('JWT_SECRET', 'super-secret-key')
        payload = jwt.decode(
            token,
            secret,
            algorithms=['HS256']
        )

        user = User.query.get(payload['user_id'])
        if not user:
            return jsonify({"msg": "Usuario no encontrado"}), 404

        return jsonify({
            "msg": "Acceso permitido",
            "email": user.email
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"msg": "Token expirado"}), 401
    except Exception:
        return jsonify({"msg": "Token inválido"}), 401
