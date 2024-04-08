import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from prometheus_flask_exporter import PrometheusMetrics


from .database import db
from .jwt_handlers import configure_jwt_handlers

metrics = PrometheusMetrics.for_app_factory()
migrate = Migrate()
jwt = JWTManager()
def create_app():
    app = Flask(__name__)

    from .controllers.user_controller import user
    
    from .models.user_model import User
    from .models.user_model import TokenBlocklist
    
    app.register_blueprint(user)

    app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:123456@db:5432/banco_de_dados"
    app.config["JWT_SECRET_KEY"] = "dev"  
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 200
    
    CORS(app)
    db.init_app(app)
    migrate.init_app(app,db)
    jwt.init_app(app)
    metrics.init_app(app)
    configure_jwt_handlers(jwt)

    
    return app