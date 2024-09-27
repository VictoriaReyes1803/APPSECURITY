from flask import jsonify, request
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app.models import User, db, Message

import hashlib
import datetime
import os

class AuthController:
    @staticmethod
    def register():
        data = request.get_json()
        salt, hashed_password = AuthController.hash_password_sha256(data['password'])

        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, salt=salt)
        
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'Usuario registrado exitosamente'}), 201

    @staticmethod
    def login():
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()

        if not user:
            return jsonify({'message': 'Credenciales incorrectas'}), 401

        hashed_input_password = hashlib.sha256(bytes.fromhex(user.salt) + data['password'].encode('utf-8')).hexdigest()

        if hashed_input_password != user.password_hash:
            return jsonify({'message': 'Credenciales incorrectas'}), 401
        
        user.state = True
        db.session.commit()

        expires = datetime.timedelta(minutes=120)
        access_token = create_access_token(identity=user.id, expires_delta=expires)
        
        
        return jsonify({'access_token': access_token}), 200

    @staticmethod
    def protected():
        return jsonify({'message': '¡Has accedido a un recurso protegido!'}), 200

    @staticmethod
    def hash_password_sha256(password):
        salt = os.urandom(16)
        hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        return salt.hex(), hashed_password

class MessageController:
    @staticmethod
    def get_user_key(user_id):
        """ Obtener la clave de cifrado del usuario """
        user = User.query.get(user_id)
        if user is None:
            raise ValueError(f"No user found with id {user_id}")  
        return user.encryption_key.encode('utf-8')  

    @staticmethod
    def encrypt_message(message, key):
        """ Cifrar el mensaje con la clave del usuario """
        cipher_suite = Fernet(key)
        return cipher_suite.encrypt(message.encode('utf-8'))

    @staticmethod
    def decrypt_message(encrypted_message, key):
        """ Descifrar el mensaje con la clave del usuario """
        cipher_suite = Fernet(key)
        return cipher_suite.decrypt(encrypted_message).decode('utf-8')

    @staticmethod
    @jwt_required()
    def send_message():
        data = request.get_json()
        current_user = get_jwt_identity()
        recipient_id = data['recipient_id']

        try:
            recipient_key = MessageController.get_user_key(recipient_id)
        except ValueError as e:
            return jsonify({'message': str(e)}), 404  

        # primera encriptacion vicky
        encrypted_message = MessageController.encrypt_message(data['content'], recipient_key)

        
        new_message = Message(
            sender_id=current_user,
            recipient_id=recipient_id,
            content=encrypted_message
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        return jsonify({'message': 'Mensaje cifrado y enviado'}), 201

    @staticmethod
    @jwt_required()
    def get_messages(user_id):
        current_user = get_jwt_identity()

        # Obtener la clave del usuario actual para descifrar
        user_key = MessageController.get_user_key(current_user)
        
        messages = Message.query.filter(
            ((Message.sender_id == current_user) & (Message.recipient_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.recipient_id == current_user))
        ).all()

        # Descifrar los mensajes
        decrypted_messages = [{
            'id': message.id,
            'sender_id': message.sender_id,
            'recipient_id': message.recipient_id,
            'content': MessageController.decrypt_message(message.content, user_key),
            'timestamp': message.timestamp.isoformat()
        } for message in messages]
        
        return jsonify(decrypted_messages), 200