from flask import Flask, jsonify
from flask_cors import CORS
import os

def create_app():
    app = Flask(__name__)
    CORS(app)

    @app.route("/")
    def home():
        return "Bem vindo a pagina inicial. Verificando mudancas."
    return app