from flask import Blueprint, jsonify, request
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token, jwt_required
from app.models import User, db
import hashlib
import datetime
import os

routes = Blueprint('routes', __name__)

def hash_password_sha256(password):
    salt = os.urandom(16)
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return salt.hex(), hashed_password  # Convierte el salt a hexadecimal para almacenarlo

@routes.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    salt, hashed_password = hash_password_sha256(data['password'])  # Captura el salt y el hash

    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, salt=salt)  # Almacena el salt
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

@routes.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'Credenciales incorrectas'}), 401

    hashed_input_password = hashlib.sha256(bytes.fromhex(user.salt) + data['password'].encode('utf-8')).hexdigest()

    if hashed_input_password != user.password_hash:
        return jsonify({'message': 'Credenciales incorrectas'}), 401

    # Crear token de acceso válido por 120 minutos
    expires = datetime.timedelta(minutes=120)
    access_token = create_access_token(identity=user.id, expires_delta=expires)

    return jsonify({'access_token': access_token}), 200

@routes.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({'message': '¡Has accedido a un recurso protegido!'}), 200
