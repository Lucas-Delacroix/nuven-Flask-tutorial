# jwt_handlers.py
from flask import jsonify
from .models.user_model import TokenBlocklist
from flask_jwt_extended import JWTManager, create_access_token, decode_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt


def configure_jwt_handlers(jwt: JWTManager):    
   
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({"statusCode":"401","name":"error", "message":"Invalid, non-existent or empty token"}), "401"

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({"statusCode":"401", "name":"error", "message":"Invalid, non-existent or empty token"}), "401"

    @jwt.token_in_blocklist_loader
    def check_if_token_is_revoked(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        token = TokenBlocklist.query.filter_by(jti=jti).first()
        return token is not None
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({"statusCode":"400", "name":"error", "message":"Token has been revoked"}), "400"

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"statusCode":"401", "name":"error", "message":"Token has expired"}), "401"
