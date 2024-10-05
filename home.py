#home.py

from flask import request
from app import create_app
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
import eventlet
eventlet.monkey_patch()
app = create_app.create_app()
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    print("Cliente conectado")
    emit('response', {'data': 'Conexión establecida con éxito'})

@socketio.on('disconnect')
def handle_disconnect():
    print("Cliente desconectado")

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    print(f'Usuario se unió a la sala: {room}')
    socketio.emit('join_confirmation', {'room': room}, to=request.sid)

@socketio.on('check_rooms')
def check_rooms():
    sid = request.sid
    client_rooms = rooms(sid)
    print(f'El cliente está suscrito a las siguientes salas: {client_rooms}')
    socketio.emit('list_rooms', client_rooms)
    
    
@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data['sender_id']
    recipient_id = data['recipient_id']
    message = data['content']

    room_name = f"chat_{min(sender_id, recipient_id)}_{max(sender_id, recipient_id)}"

    join_room(room_name)
    socketio.emit('new_message', {
        'sender_id': sender_id,
        'recipient_id': recipient_id,
        'content': message
    }, room=room_name)

    print(f'El usuario {sender_id} envió un mensaje a {recipient_id} en la sala {room_name}')

@socketio.on('join_room')
def handle_join_room(data):
    user_id = data['user_id']
    room_name = data['room_name']
    join_room(room_name)
    print(f'Usuario {user_id} se unió a la sala {room_name}')

@socketio.on('leave_room')
def handle_leave_room(data):
    user_id = data['user_id']
    room_name = data['room_name']
    leave_room(room_name)
    print(f'Usuario {user_id} salió de la sala {room_name}')

if __name__ == "__main__":
    socketio.run(app)
