from flask import Blueprint
from app.controllers import AuthController, MessageController

routes = Blueprint('routes', __name__)

# Rutas de autenticación
routes.add_url_rule('/api/register', view_func=AuthController.register, methods=['POST'])
routes.add_url_rule('/api/login', view_func=AuthController.login, methods=['POST'])
routes.add_url_rule('/api/logout', view_func=AuthController.logout, methods=['PUT', 'OPTIONS'])
routes.add_url_rule('/protected', view_func=AuthController.protected, methods=['GET', 'OPTIONS'])

# Rutas de mensajería
routes.add_url_rule('/api/messages', view_func=MessageController.send_message, methods=['POST', 'OPTIONS'])
routes.add_url_rule('/api/menu', view_func=MessageController.get_active_users, methods=['GET', 'OPTIONS'])
routes.add_url_rule('/api/messages/<int:user_id>', view_func=MessageController.get_messages, methods=['GET', 'OPTIONS'])