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
    
    
    hash_senha = generate_password_hash(data["password"], method='pbkdf2:sha256')
    
    user = User(email=data["email"], password=hash_senha)

    try:
        db.session.add(user)
        db.session.commit()
        return jsonify({"error":False, "message": "O usuário foi cadastrado com sucesso."})
    
    except:
        db.session.rollback()
        return jsonify({"error":True, "message": "Erro ao cadastrar usuário, informações já existem no banco."})

@user.route("/user/login", methods=["POST"])
def login():
    data = request.get_json()
    """
    Seção de tratamento de erro.
    """
    email_em_branco = "email" not in data or data["email"] is None or data["email"] == ""
    senha_em_branco = "password" not in data or data["password"] is None or data["password"] == ""
    data_none = data is None or data == "" or data == {}

    if data_none:
        return jsonify({"statusCode":"400", "name":"error", "message":"login falhou"}), "400"

    if (email_em_branco) or (senha_em_branco):
        return jsonify({"statusCode":"400", "name":"error", "message":"login falhou"}), "400"
    
    user = User.query.filter_by(email=data["email"]).first()
    if user is None:
        return jsonify({ "statusCode":"401", "name":"error", "message":"login falhou"}), "401"

    if check_password_hash(user.password, data["password"]) == False:
        return jsonify({ "statusCode":"401", "name":"error", "message":"login falhou"}), "401"
    
    created = datetime.now()
    access_token = create_access_token(identity=user.email)
    
    #Decodificação do token JWT para obter o tempo de expiração (TLL), feito de acordo com as especificações e casos de teste.
    decoded_token = decode_token(access_token)
    token_ttl = decoded_token['exp'] - decoded_token['iat']

    return jsonify({ "token": access_token, "ttl": token_ttl, "created": created, "userId": user.id})


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

    