from flask import Blueprint, request, jsonify
from app.models import User
from app.utils import generate_jwt, decode_jwt, encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa, generate_aes_key
from app.database import get_db_connection
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from config import SECRET_KEY
from flask_cors import CORS

bp = Blueprint('routes', __name__)

CORS(bp, resources={r"/*": {"origins": "http://localhost:3000"}})

@bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user = User(username=data['username'], password=data['password'])
    user.save()
    return jsonify({'message': 'Usuario registrado com sucesso!'}), 201

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.find_by_username(data['username'])
    if user and User.verify_password(data['password'], user.password_hash):
        token = generate_jwt(user.id)
        return jsonify({'token': token}), 200
    return jsonify({'message': 'Credenciais invalidas'}), 401

@bp.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Sem token'}), 401
    try:
        token = token.split("Bearer ")[1]
    except IndexError:
        return jsonify({'message': 'Token com formato inválido'}), 401
    user_id = decode_jwt(token)
    if not user_id:
        return jsonify({'message': 'Token inválido'}), 401
    return jsonify({'message': 'Rota protegida acessada com sucesso!'}), 200

@bp.route('/encrypt', methods=['POST'])
def encrypt_message():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Sem token'}), 401
    try:
        token = token.split("Bearer ")[1]
    except IndexError:
        return jsonify({'message': 'Token com formato inválido'}), 401
    user_id = decode_jwt(token)
    if not user_id:
        return jsonify({'message': 'Token inválido'}), 401

    data = request.get_json()
    recipient_username = data.get('recipient')
    message = data.get('message')

    if not recipient_username or not message:
        return jsonify({'message': 'Destinatário e mensagem são necessários'}), 400

    sender = User.find_by_id(user_id)
    recipient = User.find_by_username(recipient_username)

    if not sender or not recipient:
        return jsonify({'message': 'Destinatário não encontrado'}), 404

    print(f"Type of recipient.public_key in routes.py: {type(recipient.public_key)}")
    print(f"Content of recipient.public_key in routes.py: {recipient.public_key[:50]}...")

    aes_key = generate_aes_key()
    encrypted_message = encrypt_aes(message, aes_key)

    recipient_public_key_bytes = recipient.public_key.encode('utf-8')

    encrypted_aes_key = encrypt_rsa(aes_key, recipient_public_key_bytes)

    if encrypted_aes_key is None:
        return jsonify({'message': 'Falha ao encriptar por AES'}), 500

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender_id, recipient_id, encrypted_message, encrypted_aes_key) VALUES (%s, %s, %s, %s)",
                   (sender.id, recipient.id, encrypted_message, encrypted_aes_key))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'Mensagem criptografada com sucesso!'}), 201

@bp.route('/decrypt', methods=['POST'])
def decrypt_message():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Sem token'}), 401

    try:
        token = token.split("Bearer ")[1]
    except IndexError:
        return jsonify({'message': 'Token com formato inválido'}), 401

    user_id = decode_jwt(token)
    if not user_id:
        return jsonify({'message': 'Token inválido'}), 401

    data = request.get_json()
    message_id = data.get('message_id')

    if not message_id:
        return jsonify({'message': 'ID da mensagem é necessário'}), 400

    recipient = User.find_by_id(user_id)

    conn = get_db_connection()
    cursor = conn.cursor()
    print(f"message_id: {message_id}, recipient.id: {recipient.id}")
    cursor.execute("SELECT sender_id, encrypted_message, encrypted_aes_key FROM messages WHERE id = %s AND recipient_id = %s",
                   (message_id, recipient.id))
    result = cursor.fetchone()
    cursor.close()
    conn.close()

    if not result:
        return jsonify({'message': 'Mensagem não encontrada ou não autorizado!'}), 404

    sender_id, encrypted_message, encrypted_aes_key = result
    sender = User.find_by_id(sender_id)

    recipient_private_key_bytes = recipient.private_key.encode('utf-8')

    aes_key = decrypt_rsa(encrypted_aes_key, recipient_private_key_bytes)

    if aes_key is None:
        return jsonify({'message': 'Falha ao descriptografar por AES'}), 500

    decrypted_message = decrypt_aes(encrypted_message, aes_key)

    return jsonify({'message': decrypted_message, 'sender': sender.username}), 200