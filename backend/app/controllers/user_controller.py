from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app.database import db 
from app.models.user_model import User, TokenBlocklist
from flask_jwt_extended import create_access_token, decode_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt, JWTManager
from flask import Blueprint
from datetime import datetime, timedelta, timezone


user = Blueprint('user', __name__)

@user.route("/user/add", methods=["POST"])
def user_add():
    data = request.get_json()

    if "email" not in data or data["email"] is None:
        return jsonify({"error":True, "message": "O email não foi informado."}), 400
    if "password" not in data or data["password"] is None:
        return jsonify({"error":True, "message": "A senha não foi informada."}), 400
    if "role_id" not in data or data["role_id"] is None:
        data["role_id"]=2
    
    hash_senha = generate_password_hash(data["password"], method='sha256')
    
    user = User(email=data["email"], password=hash_senha, role_id=data["role_id"])

    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({"error":False, "message": "O usuário foi cadastrado com sucesso."})
    
    except:
        db.session.rollback()
        return jsonify({"error":True, "message": "Erro ao cadastrar usuário, informações já existem no banco."})


@user.route("/user/list", methods=["GET"])
def user_list():
    users = User.query.all()
    arr = []
    for user in users:
        arr.append(user.to_dict())
    return jsonify({"elements": arr, "error": False})


@user.route("/user/delete/<int:id>", methods=["DELETE"])
def user_delete(id):
    user = User.query.get(id)

    if user == None:
        return jsonify({"error": True, "message": "O usuário não foi informado."})

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"error": False, "message": "Usuário deletado com sucesso."})

    except:
        db.session.rollback()
        return jsonify({"error": True, "message": "Erro ao deletar usuário."}), 200


@user.route("/user/edit/<int:id>", methods=["PUT"])
def user_edit(id):
    data = request.get_json()
    user = User.query.get(id)

    if user == None:
        return jsonify({"error": True, "message": "O usuário informado não existe."})

    try:
        if "email" in data:
            user.email = data["email"]
        
        if "password" in data:
            user.password = generate_password_hash(data["password"], method='sha256')
        
        if "role_id" in data:
            user.role_id = data["role_id"]
        
        db.session.commit()
        return jsonify({"error": False, "message": "Usuário editado com sucesso."})

    except:
        db.session.rollback()
        return jsonify({"error": True, "message": "Erro ao editar usuário."}), 200


@user.route("/user/view/<int:id>", methods=["GET"])
def user_view(id):
    user = User.query.get(id)

    if user == None:
        return jsonify({"error": True, "message": "Usuário não foi informado corretamente."})

    try:
        return jsonify({"data": user.to_dict(), "error": False})

    except:
        db.session.rollback()
        return jsonify({"error": True, "message": "Erro ao visualizar usuário."}), 200
    
@user.route("/user/logout", methods=["DELETE"])
@jwt_required() #revoke tanto refresh quanto acess token
def modify_token():
    jti = get_jwt()["jti"]
    now = datetime.now()
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return jsonify({"statusCode":"200", "message": "Logout realizado com sucesso."}), "200"

    