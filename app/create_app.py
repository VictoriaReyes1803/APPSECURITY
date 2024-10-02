# app/__init__.py

from flask import Flask
from app.config import DevelopmentConfig  
from app.models import db
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from app.routes import routes

def create_app():
    app = Flask(__name__)
    CORS(app)
    
    app.config.from_object(DevelopmentConfig)
    
    
    db.init_app(app)
    JWTManager(app)
    
    
    app.register_blueprint(routes)
    print("Rutas registradas:")
    for rule in app.url_map.iter_rules():
        print(rule)

    
    with app.app_context():
        db.create_all()

    return app
