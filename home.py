from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/Appsecurity'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Cambiar a algo más seguro en producción

# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = ''
# app.config['MYSQL_DB'] = 'mydatabase'
# app.secret_key = 'Appsecurity'

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/api/register', methods=['POST'])
def register():
    print("entro a register")
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])

    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Credenciales incorrectas'}), 401

    # Crear token de acceso válido por 30 minutos
    expires = datetime.timedelta(minutes=30)
    access_token = create_access_token(identity=user.id, expires_delta=expires)

    return jsonify({'access_token': access_token}), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({'message': '¡Has accedido a un recurso protegido!'}), 200

with app.app_context():
    db.create_all()
    
if __name__ == '__main__':
    app.run(debug=True)
