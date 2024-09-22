from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required
from app.models import User, db
import datetime

routes = Blueprint('routes', __name__)

@routes.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])

    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

@routes.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Credenciales incorrectas'}), 401

    # Crear token de acceso válido por 30 minutos
    expires = datetime.timedelta(minutes=30)
    access_token = create_access_token(identity=user.id, expires_delta=expires)

    return jsonify({'access_token': access_token}), 200

@routes.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({'message': '¡Has accedido a un recurso protegido!'}), 200
