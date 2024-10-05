#home.py

from app import create_app
from flask_socketio import SocketIO, emit, join_room
import eventlet
eventlet.monkey_patch()
app = create_app.create_app()
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    print("Cliente conectado")
    emit('response', {'data': 'Conexión establecida con éxito'})

# Evento para cuando un cliente se desconecta
@socketio.on('disconnect')
def handle_disconnect():
    print("Cliente desconectado")



if __name__ == "__main__":
    socketio.run(app, host=None, port=5000, debug=True)
