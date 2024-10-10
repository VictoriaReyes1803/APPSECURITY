from flask import app, current_app, jsonify, render_template, request, url_for
from flask_cors import CORS
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
import jwt
from app.socket import socketio 
from flask_mail import Message as MailMessage
from app.extensiones import mail
from app.models import SharedKey, User, db, Message
from flask_socketio import emit, join_room


import hashlib
import datetime
import os



class AuthController:
    @jwt_required()
    @staticmethod
    def me():
        current_user = get_jwt_identity()
        user = User.query.get(current_user)
        if user is None:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        
        return jsonify({'id': user.id, 'username': user.username, 'email': user.email, 'state': user.state}), 200
    
    @staticmethod
    def options_login():
        return jsonify({'message': 'Opciones para la ruta login'}), 200
    @staticmethod
    def register():
        data = request.get_json()
        salt, hashed_password = AuthController.hash_password_sha256(data['password'])

        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, salt=salt)
        
        db.session.add(new_user)
        db.session.commit()

        token = jwt.encode({'user_id': new_user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)},
                           current_app.config['SECRET_KEY'], algorithm='HS256')

        verification_link = f"http://localhost:5000/api/verify/{token}"
        
        msg = MailMessage(subject="Verificación de Correo",
                      recipients=[data['email']],
                      )
       
        
        msg.html = render_template('verification_email.html', username=data['username'], verification_link=verification_link)
        mail.send(msg)       
        
        return jsonify({'message': 'Usuario registrado exitosamente'}), 201

    @staticmethod
    def verify(token):
        try:

            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(data['user_id'])
            
            if not user:
                return jsonify({'message': 'Usuario no encontrado'}), 404


            user.state = True
            db.session.commit()

            return render_template('verification_success.html', username=user.username)
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'El enlace de verificación ha expirado'}), 400
        except jwt.InvalidTokenError:
            return jsonify({'message': 'El token es inválido'}), 400
    
    
    
    @staticmethod
    def login():
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()

        if not user:
            return jsonify({'message': 'Credenciales incorrectas'}), 401
        
        if user.state == False:
            return jsonify({'message': 'Cuenta no verificada'}), 401    
        

        hashed_input_password = hashlib.sha256(bytes.fromhex(user.salt) + data['password'].encode('utf-8')).hexdigest()

        if hashed_input_password != user.password_hash:
            return jsonify({'message': 'Credenciales incorrectas'}), 401
        
        user.is_active = True
        db.session.commit()

        expires = datetime.timedelta(hours=24)
        access_token = create_access_token(identity=user.id, expires_delta=expires)
        
        
        return jsonify({'access_token': access_token,
                        'id': user.id, 'username': user.username, 'email': user.email, 'state': user.state}), 200

    @staticmethod
    @jwt_required()
    def logout():
        current_user = get_jwt_identity()
        user = User.query.get(current_user)
        if user is None:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        
        user.is_active = False
        db.session.commit()

        return jsonify({'message': 'Saliendo de tu cuenta...'}), 200


    @staticmethod
    def protected():
        return jsonify({'message': '¡Has accedido a un recurso protegido!'}), 200

    @staticmethod
    def hash_password_sha256(password):
        salt = os.urandom(16)
        hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
        return salt.hex(), hashed_password

class MessageController:
    def __init__(self):
        from app.create_app import socketio
        
    @staticmethod
    @jwt_required()
    def get_active_users():
        current_user_id = get_jwt_identity()
        users = User.query.filter_by(state=True).filter(User.id != current_user_id).all() 
        user_list = [{'id': user.id, 'name': user.username, 'email': user.email} for user in users]
        
        return jsonify({'usuarios': user_list}), 200

    @staticmethod
    def get_shared_key(user1_id_, user2_id_):
        """ Obtener o crear una clave compartida para dos usuarios. """
        
        user1_id = int(user1_id_)
        user2_id = int(user2_id_)
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id

        shared_key_entry = SharedKey.query.filter_by(user1_id=user1_id, user2_id=user2_id).first()

        if shared_key_entry:
            return shared_key_entry.key

        new_key = Fernet.generate_key()

        new_shared_key = SharedKey(user1_id=user1_id, user2_id=user2_id, key=new_key)
        db.session.add(new_shared_key)
        db.session.commit()

        return new_key
    
    
    @staticmethod
    def generate_key(user_id):
        """ Obtener la clave de cifrado del usuario """
        return Fernet.generate_key()

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

        shared_key = MessageController.get_shared_key(current_user, recipient_id)
        if shared_key is None:
            return jsonify({'message': 'Error al obtener la clave compartida'}), 500

        # primera encriptacion vicky
        encrypted_message = MessageController.encrypt_message(data['content'], shared_key)

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

        shared_key = MessageController.get_shared_key(current_user, user_id)
        if shared_key is None:
            return jsonify({'message': 'Error al obtener la clave compartida'}), 500
        
        messages = Message.query.filter(
            ((Message.sender_id == current_user) & (Message.recipient_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.recipient_id == current_user))
        ).all()

        decrypted_messages = []
        for message in messages:
            try:
                decrypted_content = MessageController.decrypt_message(message.content, shared_key)
                decrypted_messages.append({
                    'id': message.id,
                    'sender_id': message.sender_id,
                    'recipient_id': message.recipient_id,
                    'content': decrypted_content,
                    'timestamp': message.timestamp.isoformat()
                })
            except Exception as e:
                print(f"Error al descifrar el mensaje {message.id}: {str(e)}")
                continue
        
        return jsonify(decrypted_messages), 200

