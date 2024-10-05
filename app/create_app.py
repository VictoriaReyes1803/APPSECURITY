# create_app.py
import eventlet
eventlet.monkey_patch()
from flask import Flask

from app.config import DevelopmentConfig  
from app.models import db
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from app.routes import routes
from flask_socketio import SocketIO
socketio = SocketIO(cors_allowed_origins="*")

def create_app():
    app = Flask(__name__)
    jwt = JWTManager(app)

    CORS(app)  
    
    app.config.from_object(DevelopmentConfig)

    db.init_app(app)
   
    with app.app_context():
        app.register_blueprint(routes)
        db.create_all()

    socketio.init_app(app)

    print("Rutas registradas:")
    for rule in app.url_map.iter_rules():
        print(rule)

    return app