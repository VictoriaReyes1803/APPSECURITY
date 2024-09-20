from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/api/saludo', methods=['GET'])
def saludo():
    return jsonify({'mensaje': 'Hola, bienvenido a la API de Flask'})



if __name__ == '__main__':
    app.run(debug=True)
