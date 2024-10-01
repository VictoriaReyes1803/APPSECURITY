from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet

import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False) 
    encryption_key = db.Column(db.String(128), nullable=False)
    state = db.Column(db.Boolean, default=False)
    

    def __init__(self, username, email, password_hash, salt):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.salt = salt
        self.encryption_key = Fernet.generate_key().decode('utf-8')
        


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

class SharedKey(db.Model):
    __tablename__ = 'shared_keys'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.LargeBinary, nullable=False)

    def __repr__(self):
        return f'<SharedKey {self.user1_id} <-> {self.user2_id}>'