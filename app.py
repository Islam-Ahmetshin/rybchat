import sqlite3
from flask import Flask, render_template, request, redirect, g, flash
import os
import re
import html
import logging
import time
import secrets
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError

from flask_talisman import Talisman

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = False

# КОНФИГУРАЦИЯ БЕЗОПАСНОСТИ
app.config.update(
    DATABASE='board.db',
    UPLOAD_FOLDER='static/emojis',
    MAX_EMOJI_SIZE=120 * 1024,  # 120KB
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg'},
    SECRET_KEY=os.environ.get('SECRET_KEY', 'change-this-in-production-' + secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # True в продакшене с HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
    WTF_CSRF_ENABLED=False, # НА ХОСТЕ True
    WTF_CSRF_TIME_LIMIT=3600
)

# ИНИЦИАЛИЗАЦИЯ СИСТЕМ ЗАЩИТЫ
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Talisman для security headers (отключен для разработки, включить в продакшене)
# talisman = Talisman(
#     app,
#     content_security_policy={
#         'default-src': "'self'",
#         'img-src': ["'self'", "data:"],
#         'style-src': ["'self'"],
#         'script-src': ["'self'"]
#     },
#     force_https=False
# )

# АДМИНИСТРАТИВНЫЙ ТОКЕН
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', secrets.token_hex(32))

# Создаем папку для эмодзи
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# НАСТРОЙКА ЛОГИРОВАНИЯ
def setup_logging():
    """Настройка системы логирования для безопасности"""
    os.makedirs('logs', exist_ok=True)
    handler = RotatingFileHandler(
        'logs/app.log', 
        maxBytes=10000, 
        backupCount=3
    )
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

setup_logging()

def get_db():
    """
    Получаем соединение с базой данных с настройками безопасности
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            timeout=30,
            check_same_thread=False
        )
        g.db.row_factory = sqlite3.Row
        
        # Настройки безопасности SQLite
        g.db.execute('PRAGMA journal_mode = WAL')
        g.db.execute('PRAGMA foreign_keys = ON')
        g.db.execute('PRAGMA secure_delete = ON')  # Полное удаление данных
        g.db.execute('PRAGMA auto_vacuum = INCREMENTAL')
        g.db.execute('PRAGMA max_page_count = 100000')  # Лимит от DoS
    return g.db

def close_db(e=None):
    """Закрываем соединение с БД при завершении запроса"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Инициализация базы данных с созданием таблиц"""
    with app.app_context():
        db = get_db()
        
        # Таблица постов
        db.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица эмодзи
        db.execute('''
            CREATE TABLE IF NOT EXISTS emojis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        db.commit()

app.teardown_appcontext(close_db)

def allowed_file(filename):
    """Проверяем, что файл имеет разрешенное расширение"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_input(text, max_length=255, allowed_chars=None):
    """
    ВАЛИДАЦИЯ ВВОДА - защита от SQL-инъекций и XSS
    """
    if text is None:
        return None
    
    # Убираем лишние пробелы
    text = text.strip()
    
    # Проверяем длину
    if len(text) > max_length:
        return None
    
    # Проверяем на опасные SQL конструкции
    sql_injection_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|ALTER|CREATE|TRUNCATE)\b)',
        r'(\-\-|\#|\/\*)',  # SQL комментарии
        r'(\b(OR|AND)\b.*\=.*\=)',
        r'(\b(SLEEP|BENCHMARK|WAITFOR)\b)',
        r'(\b(LOAD_FILE|INTO_FILE|INTO OUTFILE)\b)'
    ]
    
    for pattern in sql_injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            app.logger.warning(f"SQL injection attempt detected: {text}")
            return None
    
    # Дополнительная проверка для специальных случаев
    if allowed_chars:
        if not re.match(allowed_chars, text):
            return None
    
    return text

def safe_render_text(text):
    """
    Экранирование HTML символов для защиты от XSS
    """
    if text is None:
        return ""
    return html.escape(text)

def safe_db_execute(query, params=(), fetch=False, fetchall=False):
    """
    БЕЗОПАСНОЕ ВЫПОЛНЕНИЕ SQL ЗАПРОСОВ
    
    """
    try:
        db = get_db()
        cursor = db.execute(query, params)
        
        if fetch:
            result = cursor.fetchone()
        elif fetchall:
            result = cursor.fetchall()
        else:
            db.commit()
            result = cursor.lastrowid
        
        cursor.close()
        return result
    except sqlite3.Error as e:
        # Логируем ошибки, но не показываем пользователю детали БД
        app.logger.error(f"Database error: {e}")
        db.rollback()
        return None

def validate_uploaded_file(file):
    """
    Расширенная проверка загружаемых файлов
    """
    if not file or file.filename == '':
        return False, "Файл не выбран"
    
    # Проверка расширения
    if not allowed_file(file.filename):
        return False, "Разрешены только JPG и PNG файлы"
    
    # Проверка размера
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)
    
    if file_length > app.config['MAX_EMOJI_SIZE']:
        return False, "Файл слишком большой"
    
    # Базовая проверка на вредоносные файлы
    try:
        content = file.read(4096)  # Читаем первые 4KB
        file.seek(0)
        
        malicious_patterns = [
            b'<?php',
            b'<script',
            b'eval(',
            b'exec(',
            b'system('
        ]
        
        for pattern in malicious_patterns:
            if pattern in content:
                app.logger.warning(f"Malicious file detected: {file.filename}")
                return False, "Файл заблокирован по соображениям безопасности"
    except Exception as e:
        app.logger.error(f"File validation error: {e}")
        return False, "Ошибка проверки файла"
    
    return True, "OK"

def replace_emojis_in_text(text):
    """Заменяет коды эмодзи на HTML изображения в тексте"""
    # Валидируем входной текст
    safe_text = validate_input(text, max_length=1000)
    if not safe_text:
        return ""
    
    # Используем безопасный запрос к БД
    emojis = safe_db_execute('SELECT * FROM emojis', fetchall=True)
    
    if not emojis:
        return safe_text
    
    for emoji in emojis:
        code = f":{emoji['code']}:"
        # Используем безопасное создание HTML
        img_tag = f'<img src="/static/emojis/{html.escape(emoji["filename"])}" class="emoji" alt="{html.escape(code)}">'
        safe_text = safe_text.replace(code, img_tag)
    
    return safe_text

@app.after_request
def set_security_headers(response):
    """
    Установка security headers для защиты браузера
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/')
def welcome():
    """Приветственная страница"""
    start_time = time.time()
    ip_address = request.remote_addr
    
    try:
        # Используем безопасные запросы
        posts_count_result = safe_db_execute('SELECT COUNT(*) FROM posts', fetch=True)
        emojis_count_result = safe_db_execute('SELECT COUNT(*) FROM emojis', fetch=True)
        emojis = safe_db_execute('SELECT * FROM emojis ORDER BY code', fetchall=True)
        
        posts_count = posts_count_result[0] if posts_count_result else 0
        emojis_count = emojis_count_result[0] if emojis_count_result else 0
        
        app.logger.info(f"Welcome page accessed from IP {ip_address}")
        return render_template('welcome.html', 
                             posts_count=posts_count, 
                             emojis_count=emojis_count,
                             emojis=emojis)
    except Exception as e:
        app.logger.error(f"Error in welcome page for IP {ip_address}: {str(e)}")
        flash('Временная ошибка сервера', 'error')
        return render_template('welcome.html', posts_count=0, emojis_count=0, emojis=[])
    finally:
        duration = time.time() - start_time
        app.logger.debug(f"Welcome request from {ip_address} took {duration:.2f}s")

@app.route('/board')
def board():
    """Основная доска с постами"""
    start_time = time.time()
    ip_address = request.remote_addr
    
    try:
        # Безопасный запрос к БД
        posts = safe_db_execute('SELECT * FROM posts ORDER BY created_at DESC', fetchall=True)
        
        if not posts:
            app.logger.info(f"Board accessed - no posts from IP {ip_address}")
            return render_template('board.html', posts=[])
        
        # Заменяем эмодзи в сообщениях
        processed_posts = []
        for post in posts:
            processed_post = dict(post)
            # Экранируем все пользовательские данные
            processed_post['name'] = safe_render_text(post['name'])
            processed_post['message'] = replace_emojis_in_text(post['message'])
            processed_posts.append(processed_post)
        
        app.logger.info(f"Board accessed with {len(posts)} posts from IP {ip_address}")
        return render_template('board.html', posts=processed_posts)
    except Exception as e:
        app.logger.error(f"Error in board page for IP {ip_address}: {str(e)}")
        flash('Временная ошибка сервера', 'error')
        return render_template('board.html', posts=[])
    finally:
        duration = time.time() - start_time
        app.logger.debug(f"Board request from {ip_address} took {duration:.2f}s")

@app.route('/add', methods=['POST'])
@limiter.limit("10 per minute")  # Защита от спама
def create_post():
    """
    СОЗДАНИЕ ПОСТА С ЗАЩИТОЙ ОТ SQL-ИНЪЕКЦИЙ И XSS
    """
    start_time = time.time()
    ip_address = request.remote_addr
    
    try:
        # Валидируем имя
        raw_name = request.form.get('name')
        name = validate_input(
            raw_name, 
            max_length=16,
            allowed_chars=r'^[a-zA-Zа-яА-Я0-9_\-]{3,16}$'
        )
        
        if not name:
            name = "Аноним"
        
        # Дополнительная проверка имени
        if ' ' in name:
            name = "Аноним"
        
        # Валидируем сообщение
        raw_message = request.form.get('message', '')
        message = validate_input(raw_message, max_length=255)
        
        if not message:
            flash('Сообщение не может быть пустым', 'error')
            return redirect('/board')
        
        # БЕЗОПАСНАЯ ВСТАВКА В БАЗУ ДАННЫХ
        success = safe_db_execute(
            'INSERT INTO posts (name, message) VALUES (?, ?)', 
            (name, message)
        )
        
        if success:
            app.logger.info(f"Post created by {name} from IP {ip_address}")
            flash('Сообщение добавлено!', 'success')
        else:
            app.logger.error(f"Failed to create post from IP {ip_address}")
            flash('Ошибка при сохранении сообщения', 'error')
        
        return redirect('/board')
    except Exception as e:
        app.logger.error(f"Error creating post from IP {ip_address}: {str(e)}")
        flash('Ошибка при создании сообщения', 'error')
        return redirect('/board')
    finally:
        duration = time.time() - start_time
        app.logger.debug(f"Create post from {ip_address} took {duration:.2f}s")

@app.route('/add_emoji', methods=['POST'])
@limiter.limit("5 per hour")  # Защита от злоупотребления
def add_emoji():
    """Добавление нового эмодзи с защитой от инъекций"""
    start_time = time.time()
    ip_address = request.remote_addr
    
    try:
        # Валидируем код эмодзи
        raw_code = request.form.get('code', '').strip()
        code = validate_input(
            raw_code,
            max_length=4,
            allowed_chars=r'^[A-Za-z0-9]{4}$'
        )
        
        if not code:
            flash('Код эмодзи должен быть ровно 4 символа (буквы и цифры)', 'error')
            return redirect('/')
        
        # Валидируем имя пользователя
        raw_uploaded_by = request.form.get('name', '').strip()
        uploaded_by = validate_input(
            raw_uploaded_by,
            max_length=16,
            allowed_chars=r'^[a-zA-Zа-яА-Я0-9_\-]{3,16}$'
        )
        
        if not uploaded_by:
            uploaded_by = "Аноним"
        
        file = request.files.get('emoji_image')
        
        # Проверка файла
        if not file or file.filename == '':
            flash('Выберите файл для эмодзи', 'error')
            return redirect('/')
        
        # Расширенная проверка файла
        file_valid, file_message = validate_uploaded_file(file)
        if not file_valid:
            flash(file_message, 'error')
            return redirect('/')
        
        # Проверяем лимит эмодзи безопасным запросом
        emojis_count_result = safe_db_execute('SELECT COUNT(*) FROM emojis', fetch=True)
        emojis_count = emojis_count_result[0] if emojis_count_result else 0
        
        if emojis_count >= 1001:
            flash('Достигнут лимит эмодзи (1001). Новые нельзя добавить.', 'error')
            return redirect('/')
        
        # Проверяем, не занят ли код безопасным запросом
        existing = safe_db_execute(
            'SELECT id FROM emojis WHERE code = ?', 
            (code,), 
            fetch=True
        )
        
        if existing:
            flash('Этот код эмодзи уже занят', 'error')
            return redirect('/')
        
        # Сохраняем файл
        filename = secure_filename(f"{code}.{file.filename.rsplit('.', 1)[1].lower()}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Безопасное добавление в базу
        success = safe_db_execute(
            'INSERT INTO emojis (code, filename, uploaded_by) VALUES (?, ?, ?)',
            (code, filename, uploaded_by)
        )
        
        if success:
            app.logger.info(f"Emoji :{code}: added by {uploaded_by} from IP {ip_address}")
            flash(f'Эмодзи :{code}: успешно добавлен!', 'success')
        else:
            app.logger.error(f"Failed to add emoji from IP {ip_address}")
            flash('Ошибка при добавлении эмодзи', 'error')
            # Удаляем файл если запись в БД не удалась
            try:
                os.remove(file_path)
            except OSError:
                pass
        
        return redirect('/')
    except Exception as e:
        app.logger.error(f"Error adding emoji from IP {ip_address}: {str(e)}")
        flash('Ошибка при добавлении эмодзи', 'error')
        return redirect('/')
    finally:
        duration = time.time() - start_time
        app.logger.debug(f"Add emoji from {ip_address} took {duration:.2f}s")

@app.route('/emojis')
def emojis_list():
    """Страница со списком всех эмодзи"""
    start_time = time.time()
    ip_address = request.remote_addr
    
    try:
        # Безопасный запрос
        emojis = safe_db_execute('SELECT * FROM emojis ORDER BY code', fetchall=True)
        app.logger.info(f"Emojis list accessed from IP {ip_address}")
        return render_template('emojis.html', emojis=emojis or [])
    except Exception as e:
        app.logger.error(f"Error in emojis list for IP {ip_address}: {str(e)}")
        flash('Временная ошибка сервера', 'error')
        return render_template('emojis.html', emojis=[])
    finally:
        duration = time.time() - start_time
        app.logger.debug(f"Emojis request from {ip_address} took {duration:.2f}s")

@app.route('/clear')
@limiter.limit("1 per hour")  # Защита от злоупотребления
def clear_posts():
    """
    Очистка всех постов с защитой токеном
    """
    start_time = time.time()
    ip_address = request.remote_addr
    
    try:
        # Проверка административного токена
        token = request.args.get('token')
        if token != ADMIN_TOKEN:
            app.logger.warning(f"Unauthorized clear attempt from IP {ip_address}")
            flash('Неавторизованный доступ', 'error')
            return redirect('/')
        
        success = safe_db_execute('DELETE FROM posts')
        safe_db_execute('DELETE FROM sqlite_sequence WHERE name="posts"')
        
        if success:
            app.logger.info(f"Posts cleared by admin from IP {ip_address}")
            flash('Все сообщения очищены', 'success')
        else:
            app.logger.error(f"Failed to clear posts from IP {ip_address}")
            flash('Ошибка при очистке сообщений', 'error')
            
        return redirect('/board')
    except Exception as e:
        app.logger.error(f"Error clearing posts from IP {ip_address}: {str(e)}")
        flash('Ошибка при очистке сообщений', 'error')
        return redirect('/board')
    finally:
        duration = time.time() - start_time
        app.logger.debug(f"Clear posts from {ip_address} took {duration:.2f}s")

@app.route('/health')
def health_check():
    """
    Проверка состояния приложения (без чувствительной информации)
    """
    try:
        # Проверяем БД
        db_status = safe_db_execute('SELECT 1', fetch=True) is not None
        # Проверяем файловую систему
        disk_status = os.path.exists(app.config['UPLOAD_FOLDER'])
        
        status = 'healthy' if db_status and disk_status else 'degraded'
        
        app.logger.debug(f"Health check: {status}")
        return {
            'status': status,
            'database': 'connected' if db_status else 'disconnected',
            'storage': 'available' if disk_status else 'unavailable',
            'timestamp': time.time()
        }
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return {'status': 'unhealthy'}, 500

@app.errorhandler(404)
def not_found_error(error):
    """Обработка 404 ошибок"""
    app.logger.warning(f"404 error: {request.url} from IP {request.remote_addr}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Обработка 500 ошибок"""
    app.logger.error(f"500 error: {error} from IP {request.remote_addr}")
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_error(e):
    """Обработка ошибок ограничения запросов"""
    app.logger.warning(f"Rate limit exceeded from IP {request.remote_addr}")
    flash('Слишком много запросов. Пожалуйста, попробуйте позже.', 'error')
    return redirect('/')

if __name__ == '__main__':
    init_db()

    app.logger.info("Starting Flask application...")
    app.run(debug=True, host='0.0.0.0')