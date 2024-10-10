from flask import Blueprint
from app.controllers import AuthController, MessageController

routes = Blueprint('routes', __name__)

# Rutas de autenticación
routes.add_url_rule('/api/register', view_func=AuthController.register, methods=['POST'])
routes.add_url_rule('/api/verify/<token>', view_func=AuthController.verify, methods=['GET'])
routes.add_url_rule('/api/login', view_func=AuthController.login, methods=['POST'])
routes.add_url_rule('/api/logout', view_func=AuthController.logout, methods=['POST'])  # Changed to POST
routes.add_url_rule('/protected', view_func=AuthController.protected, methods=['GET'])
routes.add_url_rule('/api/user', view_func=AuthController.me, methods=['GET'])


# Rutas de mensajería
routes.add_url_rule('/api/messages', view_func=MessageController.send_message, methods=['POST'])
routes.add_url_rule('/api/menu', view_func=MessageController.get_active_users, methods=['GET'])
routes.add_url_rule('/api/messages/<int:user_id>', view_func=MessageController.get_messages, methods=['GET'])