#!/var/www/u3279585/data/flaskenv/bin/python
"""
WSGI обработчик для Python 3.8.8
"""

import sys
import os
import logging

# Пути для Python 3.8.8
VIRTUAL_ENV = '/var/www/u3279585/data/flaskenv'
APP_DIR = '/var/www/u3279585/data/www/rybchat.ru'

# Добавляем пути из виртуального окружения для Python 3.8
sys.path.insert(0, VIRTUAL_ENV + '/lib/python3.8/site-packages')
sys.path.insert(0, APP_DIR)
os.chdir(APP_DIR)

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[logging.FileHandler(os.path.join(APP_DIR, 'passenger.log'))]
)

logging.info("=== Starting with Python 3.8.8 ===")
logging.info(f"Python executable: {sys.executable}")
logging.info(f"Python version: {sys.version}")
logging.info(f"Virtual env: {VIRTUAL_ENV}")
logging.info(f"Python path: {sys.path}")

def application(environ, start_response):
    try:
        logging.info(f"Request: {environ.get('REQUEST_METHOD')} {environ.get('PATH_INFO')}")
        
        # Импортируем Flask приложение
        from app import app
        
        # Запускаем Flask
        logging.info("Flask app started successfully")
        return app(environ, start_response)
        
    except ImportError as e:
        logging.error(f"Import error: {e}")
        
        # Фолбэк ответ с информацией о путях
        status = '200 OK'
        headers = [('Content-Type', 'text/html; charset=utf-8')]
        start_response(status, headers)
        
        debug_info = f"""
        <h2>Debug Information:</h2>
        <pre>
Python Executable: {sys.executable}
Python Version: {sys.version}
Virtual Env: {VIRTUAL_ENV}
App Dir: {APP_DIR}
Python Path:
{chr(10).join(sys.path)}
        </pre>
        """
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>РЫБЧАТ - Debug</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>🐟 РЫБЧАТ - Python 3.8.8</h1>
            <p><strong>Import Error:</strong> {str(e)}</p>
            {debug_info}
            <p>Checking virtual environment...</p>
        </body>
        </html>
        """
        return [html.encode('utf-8')]
        
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        import traceback
        logging.error(traceback.format_exc())
        
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/html; charset=utf-8')]
        start_response(status, headers)
        
        return [f"Unexpected error: {str(e)}".encode('utf-8')]
