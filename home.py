

from app import create_app
from flask_socketio import SocketIO
import eventlet
eventlet.monkey_patch()



app = create_app.create_app()

if __name__ == "__main__":
    app = create_app()
