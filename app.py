import jwt
import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'seu_segredo_aqui'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

# Rota para registro de usuário
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Usuário e senha são obrigatórios'}), 400

    # Verificar se o usuário já existe
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Usuário já existe'}), 409

    # Criptografar a senha
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Criar o usuário
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuário registrado com sucesso'}), 201

# Rota para login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Usuário e senha são obrigatórios'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Senha incorreta'}), 401

    # Gerar o token JWT
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Expira em 1 hora
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'message': 'Login bem-sucedido', 'token': token}), 200

# Rota para verificar se o usuário está autenticado
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token ausente'}), 401

    try:
        # Remover o prefixo 'Bearer ' do token
        token = token.split(" ")[1]

        # Decodificar o token
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']

        # Verificar se o usuário existe
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'Usuário não encontrado'}), 404

        return jsonify({'message': f'Usuário {user.username} autenticado com sucesso'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token inválido'}), 401

if __name__ == '__main__':
    app.run(debug=True)
