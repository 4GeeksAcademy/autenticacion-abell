

 

from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, jsonify
import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, url_for, send_from_directory
from flask_migrate import Migrate
from flasgger import Swagger
from flasgger import swag_from
from api.utils import APIException, generate_sitemap
from api.models import db
from api.routes import api
from api.admin import setup_admin
from api.commands import setup_commands

ENV = "development" if os.getenv("FLASK_DEBUG") == "1" else "production"
static_file_dir = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), '../dist/')



app = Flask(__name__)
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Autenticacion API",
        "description": "API para autenticación y gestión de usuarios. Prueba los endpoints y tokens aquí.",
        "version": "1.0.0"
    },
    "basePath": "/"
}
Swagger(app, template=swagger_template)
from flask_cors import CORS, cross_origin
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    return response
app.url_map.strict_slashes = False


load_dotenv()
if not os.path.exists('.env'):
    load_dotenv('.env.example')

db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace(
        "postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db, compare_type=True)
db.init_app(app)
setup_admin(app)
setup_commands(app)

app.register_blueprint(api, url_prefix="/")

from flasgger import swag_from
from api.models import User
from api.auth import jwt_required

@app.route('/users', methods=['GET', 'OPTIONS'])
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
def list_users(auth_user_id=None):
    if request.method == "OPTIONS":
        return '', 200
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

@app.route('/users/<int:user_id>', methods=['PUT', 'OPTIONS'])
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
    if request.method == "OPTIONS":
        return '', 200
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

@app.route('/users/<int:user_id>', methods=['DELETE', 'OPTIONS'])
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
    if request.method == "OPTIONS":
        return '', 200
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "Usuario no encontrado"}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({"msg": "Usuario eliminado"}), 200




@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code


app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY') or os.getenv('JWT_SECRET', 'super-secret-key')


@app.route('/signup', methods=['POST', 'OPTIONS'])
@swag_from({
    'tags': ['Usuarios'],
    'parameters': [
        {'name': 'body', 'in': 'body', 'required': True, 'schema': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string'},
                'password': {'type': 'string'},
                'first_name': {'type': 'string'},
                'last_name': {'type': 'string'}
            },
            'required': ['email', 'password', 'first_name', 'last_name']
        }}
    ],
    'responses': {
        201: {'description': 'Usuario creado'},
        400: {'description': 'Faltan campos requeridos o usuario ya existe'}
    }
})
def signup():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    from api.models import User
    if not email or not password or not first_name or not last_name:
        return jsonify({'msg': 'Faltan campos requeridos'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'msg': 'Usuario ya existe'}), 400
    if password is None:
        return jsonify({'msg': 'Contraseña requerida'}), 400
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    user = User(email=email, password=hashed_password,
                first_name=first_name, last_name=last_name, is_active=True)
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'Usuario creado'}), 201




@app.route('/login', methods=['POST', 'OPTIONS'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [
        {'name': 'body', 'in': 'body', 'required': True, 'schema': {
            'type': 'object',
            'properties': {
                'email': {'type': 'string'},
                'password': {'type': 'string'}
            },
            'required': ['email', 'password']
        }}
    ],
    'responses': {
        200: {'description': 'Token JWT'},
        401: {'description': 'Credenciales inválidas'}
    }
})
def login():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')

    from api.models import User
    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Credenciales inválidas'}), 401

    from api.auth import generate_token
    token = generate_token(user.id, expires_hours=2)
    return jsonify({"token": token}), 200


@app.route('/refresh', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'parameters': [
        {'name': 'body', 'in': 'body', 'required': True, 'schema': {
            'type': 'object',
            'properties': {
                'refresh_token': {'type': 'string'}
            },
            'required': ['refresh_token']
        }}
    ],
    'responses': {
        200: {'description': 'Nuevo token JWT'},
        401: {'description': 'Refresh token inválido o expirado'}
    }
})
def refresh():
    data = request.get_json() or {}
    refresh_token = data.get('refresh_token')
    if not refresh_token:
        return jsonify({'msg': 'Refresh token requerido'}), 400
    try:
        payload = jwt.decode(
            refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload.get('type') != 'refresh':
            return jsonify({'msg': 'Token inválido'}), 401
        from api.models import User
        user = User.query.get(payload.get('user_id'))
        if not user:
            return jsonify({'msg': 'Usuario no encontrado'}), 404
        access_token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=15)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        if isinstance(access_token, bytes):
            access_token = access_token.decode('utf-8')
        return jsonify({'token': access_token})
    except jwt.ExpiredSignatureError:
        return jsonify({'msg': 'Refresh token expirado'}), 401
    except Exception:
        return jsonify({'msg': 'Refresh token inválido'}), 401


from flask import redirect
@app.route("/")
def index():
    return redirect("/admin/")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=3001, debug=True)
