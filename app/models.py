from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False)  # Asegúrate de tener esta línea

    def __init__(self, username, email, password_hash, salt):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.salt = salt
