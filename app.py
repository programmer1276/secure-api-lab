import os
import jwt
import datetime
import bleach
from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# В реальном проекте секретный ключ должен быть в переменных окружения
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-lab-key-2026')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- МОДЕЛИ ДАННЫХ ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

class DataItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Создаем таблицы при первом запуске
with app.app_context():
    db.create_all()

# --- MIDDLEWARE ДЛЯ ПРОВЕРКИ JWT ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Ищем токен в заголовках
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Токен отсутствует! Доступ запрещен.'}), 401
        
        try:
            # Проверка подлинности токена
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'Неверный токен!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Срок действия токена истек!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Недействительный токен!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# --- ЭНДПОИНТЫ ---

# 0. Вспомогательный эндпоинт для регистрации (чтобы было кого логинить)
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Неверные данные'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Пользователь уже существует'}), 409

    # ЗАЩИТА: Хэширование пароля (bcrypt)
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password_hash=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Пользователь успешно зарегистрирован'}), 201

# 1. Аутентификация (POST /auth/login)
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Введите логин и пароль'}), 400

    user = User.query.filter_by(username=data['username']).first()
    
    # ЗАЩИТА: Проверка хэша пароля
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Неверный логин или пароль'}), 401

    # Генерация JWT токена
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token}), 200

# 2. Получение данных (GET /api/data) - Защищено
@app.route('/api/data', methods=['GET'])
@token_required
def get_data(current_user):
    items = DataItem.query.all()
    result = []
    for item in items:
        # ЗАЩИТА: Санитизация (экранирование) пользовательских данных для защиты от XSS
        safe_title = bleach.clean(item.title)
        safe_content = bleach.clean(item.content)
        result.append({
            'id': item.id,
            'title': safe_title,
            'content': safe_content,
            'author_id': item.author_id
        })
    return jsonify(result), 200

# 3. Добавление данных (POST /api/data) - Защищено (дополнительный метод)
@app.route('/api/data', methods=['POST'])
@token_required
def create_data(current_user):
    data = request.get_json()
    if not data or not data.get('title') or not data.get('content'):
        return jsonify({'message': 'Неверные данные'}), 400

    # ЗАЩИТА ОТ SQLi: SQLAlchemy ORM автоматически использует параметризованные запросы
    new_item = DataItem(
        title=data['title'],
        content=data['content'],
        author_id=current_user.id
    )
    db.session.add(new_item)
    db.session.commit()
    return jsonify({'message': 'Данные успешно добавлены', 'id': new_item.id}), 201

if __name__ == '__main__':
    app.run(debug=False, port=5000)
