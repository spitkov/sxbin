from flask import Flask, request, jsonify, send_from_directory, render_template, url_for, redirect, send_file, session, make_response, flash, g, Response, current_app
from werkzeug.utils import secure_filename
import shortuuid
import os
from datetime import datetime, timedelta
import zipfile
import sqlite3
import threading
import time
import shutil
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.formatters import HtmlFormatter
from pygments.util import ClassNotFound
import json
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_remembered
import hashlib
import secrets
import re
from urllib.parse import urlparse
import mimetypes

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Add this line
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DATABASE = 'data.db'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)  # Set cookie to expire after 30 day

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup and helper functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        print("Database initialized with users and content tables.")

# Call init_db() when the application starts
with app.app_context():
    init_db()

def migrate_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Check if is_private column exists
        cursor.execute("PRAGMA table_info(content)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_private' not in columns:
            print("Adding is_private column to content table")
            cursor.execute("ALTER TABLE content ADD COLUMN is_private INTEGER DEFAULT 0")
            db.commit()

# Call migrate_db() after init_db()
with app.app_context():
    init_db()
    migrate_db()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Add this function near the top of your file, after the imports
def get_username(user_id):
    if user_id is None:
        return 'Anonymous'
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return user[0] if user else 'Unknown'

# Add this function to delete old files
def delete_old_files():
    with app.app_context():
        while True:
            db = get_db()
            cursor = db.cursor()
            
            # Delete files older than 30 days
            thirty_days_ago = datetime.now() - timedelta(days=30)
            cursor.execute("SELECT vanity, type, data FROM content WHERE created_at < ?", (thirty_days_ago,))
            old_files = cursor.fetchall()
            
            for vanity, content_type, data in old_files:
                if content_type == 'file':
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{vanity}_{data}')
                    if os.path.exists(file_path):
                        os.remove(file_path)
                elif content_type == 'folder':
                    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], vanity)
                    if os.path.exists(folder_path):
                        shutil.rmtree(folder_path)
            
            cursor.execute("DELETE FROM content WHERE created_at < ?", (thirty_days_ago,))
            db.commit()
            
            time.sleep(86400)  # Sleep for 24 hours

# Start the cleanup thread
cleanup_thread = threading.Thread(target=delete_old_files)
cleanup_thread.daemon = True
cleanup_thread.start()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password_hash, api_key=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.api_key = api_key

    @staticmethod
    def hash_password(password):
        return password  # Store passwords in plaintext for simplicity

    @staticmethod
    def verify_password(stored_password, provided_password):
        return stored_password == provided_password

    @staticmethod
    def generate_api_key():
        return secrets.token_urlsafe(32)

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        # Print debug information
        print(f"User data: {user}")
        # Check if we have all required fields
        if len(user) >= 4:
            return User(user[0], user[1], user[2], user[3])
        else:
            print(f"Incomplete user data for user_id: {user_id}")
            return None
    print(f"No user found for user_id: {user_id}")
    return None

@app.route('/')
def index():
    try:
        if current_user.is_authenticated:
            return render_template('index.html', user=current_user)
    except Exception as e:
        print(f"Error in index route: {str(e)}")
    return render_template('index.html', user=None)

@app.route('/u/<username>')
@app.route('/u/<username>/')
@app.route('/u/<username>/<path:filename>')
def serve_user_page(username, filename=None):
    print(f"Accessing user page: {username}, filename: {filename}")  # Debug print

    # Check if the username exists in the database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if not user:
        print(f"User {username} not found")  # Debug print
        return "User not found", 404

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    print(f"User folder path: {user_folder}")  # Debug print
    
    if not os.path.exists(user_folder):
        print(f"User folder does not exist for {username}")  # Debug print
        os.makedirs(user_folder)  # Create the folder if it doesn't exist

    current_path = os.path.join(user_folder, filename.rstrip('/') if filename else '')
    if not os.path.exists(current_path):
        return "Folder or file not found", 404

    if os.path.isfile(current_path):
        return send_file(current_path)

    # Check if we should ignore index.html
    ignore_index = session.get(f'ignore_index_{username}', False)

    # Check for index.html
    index_path = os.path.join(current_path, 'index.html')
    if os.path.exists(index_path) and not ignore_index:
        return send_file(index_path)

    # Directory listing
    files = []
    folders = []
    for item in os.listdir(current_path):
        item_path = os.path.join(current_path, item)
        relative_path = os.path.relpath(item_path, user_folder)
        if os.path.isfile(item_path):
            files.append({'name': item, 'path': relative_path})
        else:
            folders.append({'name': item, 'path': relative_path})

    parent_folder = os.path.dirname(filename.rstrip('/')) if filename else None
    current_folder = os.path.basename(current_path)

    # Generate the correct parent folder URL
    parent_url = None
    if parent_folder:
        parent_url = url_for('serve_user_page', username=username, filename=parent_folder)
    elif filename:  # If we're in a subfolder, parent is the root
        parent_url = url_for('serve_user_page', username=username)

    return render_template('user_files_public.html', 
                           username=username, 
                           files=files, 
                           folders=folders, 
                           current_path=filename.rstrip('/') if filename else '',
                           parent_url=parent_url,
                           current_folder=current_folder)

def is_bot(user_agent):
    bot_patterns = [
        r'bot', r'spider', r'crawler', r'pinterest', r'facebook', r'twitter',
        r'slack', r'telegram', r'whatsapp', r'discord', r'embedly'
    ]
    return any(re.search(pattern, user_agent, re.I) for pattern in bot_patterns)

@app.route('/<vanity>', methods=['GET', 'POST'])
@app.route('/<vanity>/<password>', methods=['GET', 'POST'])
@app.route('/<vanity>/download', methods=['GET', 'POST'])
@app.route('/<vanity>/download/<password>', methods=['GET', 'POST'])
@app.route('/<vanity>/raw', methods=['GET', 'POST'])
@app.route('/<vanity>/raw/<password>', methods=['GET'])
def redirect_vanity(vanity, password=None):
    app.logger.info(f"Accessing redirect_vanity: vanity={vanity}, password={password}")
    app.logger.info(f"Request path: {request.path}")
    app.logger.info(f"Request method: {request.method}")
    app.logger.info(f"Request URL: {request.url}")
    app.logger.info(f"Request endpoint: {request.endpoint}")
    app.logger.info(f"Request view args: {request.view_args}")
    
    db = get_db()
    cursor = db.cursor()
    
    is_download = 'download' in request.path
    is_raw = 'raw' in request.path
    
    # First, try to find the content with the full vanity (including extension)
    cursor.execute("SELECT content.*, users.username FROM content LEFT JOIN users ON content.user_id = users.id WHERE content.vanity = ?", (vanity,))
    content = cursor.fetchone()
    
    # If not found, try without the extension
    if not content:
        vanity_without_extension = os.path.splitext(vanity)[0]
        cursor.execute("SELECT content.*, users.username FROM content LEFT JOIN users ON content.user_id = users.id WHERE content.vanity LIKE ?", (f"{vanity_without_extension}%",))
        content = cursor.fetchone()
    
    if content:
        content_type, content_data, created_at, user_id, is_private, stored_password, username = content[1], content[2], content[3], content[4], content[5], content[6], content[7]
        username = username if username else 'Anonymous'
        app.logger.info(f"Content found: type={content_type}, data={content_data}, is_private={is_private}")
        
        try:
            created_at = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            created_at = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')

        if is_private and stored_password:
            if password:
                if password != stored_password:
                    return "Incorrect password", 403
            elif request.method == 'POST':
                entered_password = request.form.get('password')
                if entered_password != stored_password:
                    return render_template('password_prompt.html', vanity=vanity, error="Incorrect password", content_type=content_type)
                password = entered_password
            else:
                return render_template('password_prompt.html', vanity=vanity, error=None, content_type=content_type)
        
        if is_raw:
            if content_type == 'pastebin':
                return content_data, 200, {'Content-Type': 'text/plain; charset=utf-8'}
            elif content_type == 'file':
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], content_data)
                mime_type, _ = mimetypes.guess_type(file_path)
                
                # Add support for .mkv files
                if file_path.lower().endswith('.mkv'):
                    mime_type = 'video/x-matroska'
                
                return send_file(file_path, mimetype=mime_type)
            elif content_type == 'url':
                return content_data, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        
        if content_type == 'url':
            user_agent = request.headers.get('User-Agent', '').lower()
            if is_bot(user_agent):
                return render_template('og_shorturl.html', long_url=content_data, username=username, created_at=created_at, vanity=vanity, is_private=is_private)
            else:
                return redirect(content_data)
        elif content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], content_data)
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                file_extension = os.path.splitext(content_data)[1].lower()
                is_embeddable = file_extension in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.pdf']
                file_url = f"{request.scheme}://{request.host}/{vanity}"
                raw_url = f"{file_url}/raw"
                
                if is_private and password:
                    raw_url += f'/{password}'
                
                if is_download:
                    return send_file(file_path, as_attachment=True)
                else:
                    return render_template('file_info.html', 
                                           filename=content_data, 
                                           file_size=file_size, 
                                           username=username, 
                                           created_at=created_at,
                                           is_embeddable=is_embeddable,
                                           file_url=file_url,
                                           raw_url=raw_url,
                                           vanity=vanity,
                                           user_id=user_id,
                                           is_private=is_private,
                                           password=password)
        elif content_type == 'pastebin':
            try:
                lexer = guess_lexer(content_data)
            except ClassNotFound:
                lexer = get_lexer_by_name('text')
            formatter = HtmlFormatter(style='monokai', linenos=True, cssclass="source")
            highlighted_content = highlight(content_data, lexer, formatter)
            css = formatter.get_style_defs('.source')
            return render_template('pastebin.html',
                                   content={'data': content_data, 'user_id': user_id, 'username': username},
                                   highlighted_content=highlighted_content,
                                   css=css,
                                   raw_content=content_data,
                                   created_at=created_at,
                                   vanity=vanity,
                                   is_private=is_private)
    
    app.logger.error(f"Content not found for vanity: {vanity}")
    return "Not found", 404

def render_pastebin(content_data, created_at, user_id, username, vanity, is_private):
    try:
        lexer = guess_lexer(content_data)
        language = lexer.aliases[0]
    except ClassNotFound:
        language = 'text'
        lexer = get_lexer_by_name(language)
    
    formatter = HtmlFormatter(style='monokai', linenos=True, cssclass="source")
    highlighted_code = highlight(content_data, lexer, formatter)
    css = formatter.get_style_defs('.source')
    return render_template('pastebin.html', 
                           content={'data': content_data, 'user_id': user_id, 'username': username or 'Anonymous'},
                           highlighted_content=highlighted_code,
                           css=css, 
                           raw_content=content_data,
                           language=language,
                           created_at=created_at,
                           vanity=vanity,
                           is_private=is_private)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and User.verify_password(user[2], password):
            user_obj = User(user[0], user[1], user[2], user[3])
            login_user(user_obj, remember=remember)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if len(password) < 5 or not any(c.isupper() for c in password):
            return jsonify({'success': False, 'error': 'Password does not meet requirements'}), 400
        
        api_key = User.generate_api_key()
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        hashed_password = User.hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash, api_key) VALUES (?, ?, ?)",
                       (username, hashed_password, api_key))
        db.commit()
        
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
        
        # Automatically log in the user
        user = User(cursor.lastrowid, username, hashed_password, api_key)
        login_user(user)
        
        return jsonify({'success': True, 'redirect': url_for('dashboard')}), 200
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dash/<username>')
@app.route('/dash/<username>/')
@app.route('/dash/<username>/<path:subpath>')
@login_required
def user_files(username, subpath=''):
    if current_user.username != username:
        return "Unauthorized", 401
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    current_path = os.path.join(user_folder, subpath.rstrip('/'))
    
    # Create user folder if it doesn't exist
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    if not os.path.exists(current_path):
        return "Folder not found", 404
    
    if not os.path.isdir(current_path):
        return "Not a directory", 400
    
    items = []
    folders = []
    for item in os.listdir(current_path):
        item_path = os.path.join(current_path, item)
        relative_path = os.path.relpath(item_path, user_folder)
        if os.path.isfile(item_path):
            items.append({'name': item, 'type': 'file', 'path': relative_path})
        else:
            items.append({'name': item, 'type': 'folder', 'path': relative_path})
            folders.append(relative_path)
    
    # Fetch user's uploads (including files, pastebins, and shortened URLs)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE user_id = ?", (current_user.id,))
    user_uploads = cursor.fetchall()
    
    uploads = []
    for upload in user_uploads:
        vanity, content_type, data, created_at, _, is_private = upload[:6]
        url = f"{request.scheme}://{request.host}/{vanity}"
        uploads.append({
            'type': content_type,
            'vanity': vanity,
            'data': data,
            'created_at': created_at,
            'is_private': is_private,
            'url': url,
            'download_url': f"{url}/download" if content_type == 'file' else None
        })
    
    parent_folder = os.path.dirname(subpath.rstrip('/')) if subpath else None
    current_folder = os.path.basename(current_path)
    
    ignore_index = session.get(f'ignore_index_{username}', False)

    return render_template('user_files.html', 
                           username=username, 
                           items=items, 
                           folders=folders, 
                           uploads=uploads,
                           current_path=subpath.rstrip('/'),
                           parent_folder=parent_folder,
                           current_folder=current_folder,
                           ignore_index=ignore_index)

@app.route('/dash/<username>/toggle_index', methods=['POST'])
@login_required
def toggle_index(username):
    if current_user.username != username:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    current_setting = session.get(f'ignore_index_{username}', False)
    new_setting = not current_setting
    session[f'ignore_index_{username}'] = new_setting
    
    return jsonify({"success": True, "ignore_index": new_setting})

@app.route('/dash/<username>/upload', methods=['POST'])
@login_required
def upload_user_file(username):
    if current_user.username != username:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    subpath = request.form.get('subpath', '').rstrip('/')
    if 'file' not in request.files:
        return jsonify({"success": False, "error": 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # Use chunked upload
        chunk_size = 4096  # 4KB chunks
        try:
            with open(file_path, 'wb') as f:
                while True:
                    chunk = file.stream.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
            
            return jsonify({"success": True, "filename": filename}), 200
        except Exception as e:
            app.logger.error(f"Error uploading file: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
    
    return jsonify({"success": False, "error": "File upload failed"}), 500

@app.route('/dash/<username>/delete/<path:filename>', methods=['POST'])
@login_required
def delete_user_file(username, filename):
    if current_user.username != username:
        return "Unauthorized", 401
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
    try:
        if os.path.exists(file_path):
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        return redirect(url_for('user_files', username=username))
    except PermissionError:
        return "Permission denied: Unable to delete the file or folder", 403
    except Exception as e:
        return f"An error occurred: {str(e)}", 500


@app.route('/dash/<username>/delete_folder/<folder_name>', methods=['POST'])
@login_required
def delete_folder(username, folder_name):
    if current_user.username != username:
        return "Unauthorized", 401
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, folder_name)
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/rename_folder', methods=['POST'])
@login_required
def rename_folder(username):
    if current_user.username != username:
        return "Unauthorized", 401
    old_foldername = request.form['old_foldername']
    new_foldername = secure_filename(request.form['new_foldername'])
    old_path = os.path.join(app.config['UPLOAD_FOLDER'], username, old_foldername)
    new_path = os.path.join(app.config['UPLOAD_FOLDER'], username, new_foldername)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/move_item', methods=['POST'])
@login_required
def move_item(username):
    if current_user.username != username:
        return "Unauthorized", 401
    item_name = request.form['item_name']
    item_type = request.form['item_type']
    destination_folder = request.form['destination_folder']
    source_path = os.path.join(app.config['UPLOAD_FOLDER'], username, item_name)
    dest_path = os.path.join(app.config['UPLOAD_FOLDER'], username, destination_folder, item_name)
    if os.path.exists(source_path):
        shutil.move(source_path, dest_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/copy_item', methods=['POST'])
@login_required
def copy_item(username):
    if current_user.username != username:
        return "Unauthorized", 401
    item_name = request.form['item_name']
    item_type = request.form['item_type']
    destination_folder = request.form['destination_folder']
    source_path = os.path.join(app.config['UPLOAD_FOLDER'], username, item_name)
    dest_path = os.path.join(app.config['UPLOAD_FOLDER'], username, destination_folder, item_name)
    if os.path.exists(source_path):
        if item_type == 'file':
            shutil.copy2(source_path, dest_path)
        else:
            shutil.copytree(source_path, dest_path)
    return redirect(url_for('user_files', username=username))

@app.route('/dash/<username>/edit/<path:filename>', methods=['GET', 'POST'])
@login_required
def edit_file(username, filename):
    if current_user.username != username:
        return "Unauthorized", 401

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, filename)
    if not os.path.exists(file_path):
        return "File not found", 404

    if request.method == 'POST':
        content = request.form['content']
        with open(file_path, 'w') as f:
            f.write(content)
        # Get the directory path to redirect back to
        dir_path = os.path.dirname(filename)
        return redirect(url_for('user_files', username=username, subpath=dir_path))

    with open(file_path, 'r') as f:
        content = f.read()

    return render_template('edit_file.html', filename=filename, content=content)

@app.route('/debug/users')
def debug_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return jsonify(users)

@app.route('/upload/pastebin', methods=['POST'])
def upload_pastebin():
    try:
        print("Received request to upload pastebin")
        data = request.get_json()
        print(f"Received JSON data: {data}")

        if not data or 'content' not in data:
            print("Error: Content is missing from the request")
            return jsonify({'success': False, 'error': 'Content is required'}), 400

        content = data['content']
        password = data.get('password')
        print(f"Content: {content[:50]}...") # Print first 50 characters of content
        print(f"Password received from client: {password}")

        is_private = 1 if password else 0
        print(f"Is private: {is_private}")

        vanity = shortuuid.uuid()[:8]
        print(f"Generated vanity: {vanity}")
        
        user_id = current_user.id if current_user.is_authenticated else "Anonymous"
        print(f"User ID: {user_id}")
        
        db = get_db()
        cursor = db.cursor()
        
        if is_private:
            print(f"Inserting private pastebin into database with password: {password}")
            cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id, is_private, password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (vanity, 'pastebin', content, datetime.now(), user_id, is_private, password))
            print(f"Executed SQL with values: {vanity}, pastebin, {content[:50]}..., {datetime.now()}, {user_id}, {is_private}, {password}")
        else:
            print("Inserting public pastebin into database")
            cursor.execute("INSERT INTO content (vanity, type, data, created_at, user_id, is_private) VALUES (?, ?, ?, ?, ?, ?)",
                           (vanity, 'pastebin', content, datetime.now(), user_id, is_private))
            print(f"Executed SQL with values: {vanity}, pastebin, {content[:50]}..., {datetime.now()}, {user_id}, {is_private}")
        
        db.commit()
        print("Database commit successful")
        
        # Verify the inserted data
        cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
        inserted_data = cursor.fetchone()
        print(f"Inserted data: {inserted_data}")
        
        short_url = f"{request.scheme}://{request.host}/{vanity}"
        deletion_url = url_for('delete_content', vanity=vanity, _external=True)
        print(f"Generated short URL: {short_url}")
        print(f"Generated deletion URL: {deletion_url}")

        return jsonify({'success': True, 'vanity': vanity, 'url': short_url, 'deletion_url': deletion_url}), 200
    except Exception as e:
        print(f"Exception occurred in upload_pastebin: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/shorten', methods=['POST'])
def shorten_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'success': False, 'error': 'URL is required'}), 400

        long_url = data['url']
        password = data.get('password')

        # Validate the URL
        parsed_url = urlparse(long_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({'success': False, 'error': 'Invalid URL'}), 400

        vanity = shortuuid.uuid()[:8]
        
        user_id = current_user.id if current_user.is_authenticated else None
        
        db = get_db()
        cursor = db.cursor()

        is_private = 1 if password else 0

        cursor.execute("""
            INSERT INTO content (vanity, type, data, created_at, user_id, is_private, password) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (vanity, 'url', long_url, datetime.now(), user_id, is_private, password))
        
        db.commit()
        
        return jsonify({'success': True, 'vanity': vanity}), 200
    except Exception as e:
        print("Exception occurred:", str(e))
        return jsonify({'success': False, 'error': str(e)}), 400

# Remove or comment out the edit_content route
# @app.route('/edit/content/<vanity>', methods=['GET', 'POST'])
# @login_required
# def edit_content(vanity):
#     ... (remove entire route)

@app.route('/edit_password/<vanity>', methods=['POST'])
@login_required
def edit_password(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
    content = cursor.fetchone()

    if not content or content[4] != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    data = request.get_json()
    action = data.get('action')
    if action == 'update':
        new_password = data.get('new_password')
        if not is_valid_password(new_password):
            return jsonify({'success': False, 'error': 'Invalid password'}), 400
        cursor.execute("UPDATE content SET password = ?, is_private = 1 WHERE vanity = ?", (new_password, vanity))
    elif action == 'remove':
        cursor.execute("UPDATE content SET is_private = 0, password = NULL WHERE vanity = ?", (vanity,))
    else:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400

    db.commit()
    return jsonify({'success': True})

@app.route('/<vanity>/delete', methods=['POST'])
@login_required
def delete_content(vanity):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT type, data, user_id FROM content WHERE vanity = ?", (vanity,))
    content = cursor.fetchone()
    
    if content and (content[2] == current_user.id):
        content_type, data = content[0], content[1]
        
        if content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], data)
            if os.path.exists(file_path):
                os.remove(file_path)
        elif content_type == 'folder':
            folder_path = os.path.join(app.config['UPLOAD_FOLDER'], vanity)
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)
        
        cursor.execute("DELETE FROM content WHERE vanity = ?", (vanity,))
        db.commit()
        
        # Check if request is AJAX
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Content deleted successfully'})
        else:
            # For regular form submissions, redirect to homepage
            flash('Content deleted successfully', 'success')
            return redirect(url_for('index'))
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': False, 'message': 'Not authorized or content not found'}), 403
    else:
        flash('Not authorized or content not found', 'error')
        return redirect(url_for('index'))

@app.route('/<vanity>/info', methods=['GET', 'POST'])
def content_info(vanity):
    db = get_db()
    cursor = db.cursor()
    
    # First, try to find the content with the full vanity (including extension)
    cursor.execute("SELECT content.*, users.username FROM content LEFT JOIN users ON content.user_id = users.id WHERE content.vanity = ?", (vanity,))
    content = cursor.fetchone()
    
    # If not found, try without the extension
    if not content:
        vanity_without_extension = os.path.splitext(vanity)[0]
        cursor.execute("SELECT content.*, users.username FROM content LEFT JOIN users ON content.user_id = users.id WHERE content.vanity LIKE ?", (f"{vanity_without_extension}%",))
        content = cursor.fetchone()
    
    if content:
        content_type, content_data, created_at, user_id, is_private, password, username = content[1], content[2], content[3], content[4], content[5], content[6], content[7]
        
        if is_private and password:
            if request.method == 'POST':
                entered_password = request.form.get('password')
                if entered_password != password:
                    return render_template('password_prompt.html', vanity=vanity, error="Incorrect password", content_type=content_type)
            else:
                return render_template('password_prompt.html', vanity=vanity, error=None, content_type=content_type)
        
        file_size = None
        if content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], content_data)
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
        
        return render_template('content_info.html', 
                               info={
                                   'type': content_type,
                                   'data': content_data,
                                   'created_at': created_at,
                                   'username': username or 'Anonymous',
                                   'is_private': is_private,
                                   'vanity': vanity,
                                   'file_size': file_size
                               })
    
    return "Content not found", 404

@app.route('/sharex-config')
@login_required
def generate_sharex_config():
    base_url = request.url_root.replace('http://', 'https://', 1).rstrip('/')
    config = {
        "Version": "13.7.0",
        "Name": "sxbin",
        "DestinationType": "ImageUploader, TextUploader, FileUploader, URLShortener",
        "RequestMethod": "POST",
        "RequestURL": f"{base_url}/upload/file",  # Changed from /api/upload to /upload/file
        "Headers": {
            "X-API-Key": current_user.api_key
        },
        "Body": "MultipartFormData",
        "FileFormName": "file",
        "URL": "$json:url$",
        "DeletionURL": "$json:deletion_url$"
    }
    
    response = make_response(json.dumps(config, indent=2))
    response.headers.set('Content-Type', 'application/json')
    response.headers.set('Content-Disposition', 'attachment', filename='sxbin_ShareX.sxcu')
    return response

@app.route('/dash/<username>/create_new_file', methods=['POST'])
@login_required
def create_new_file(username):
    if current_user.username != username:
        return "Unauthorized", 401
    subpath = request.form.get('subpath', '').rstrip('/')
    file_name = request.form['file_name']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath, file_name)
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            f.write('')
        flash(f"File '{file_name}' created successfully.", 'success')
    else:
        flash(f"File '{file_name}' already exists.", 'error')
    return redirect(url_for('user_files', username=username, subpath=subpath))

@app.route('/dash/<username>/get_folders')
@login_required
def get_folders(username):
    if current_user.username != username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    subpath = request.args.get('path', '')
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath)
    
    if not os.path.exists(folder_path):
        return jsonify({'error': 'Folder not found'}), 404
    
    folders = [f for f in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, f))]
    return jsonify(folders)

@app.route('/dash/<username>/get_folders_and_files')
@login_required
def get_folders_and_files(username):
    if current_user.username != username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    subpath = request.args.get('path', '')
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, subpath)
    
    if not os.path.exists(folder_path):
        return jsonify({'error': 'Folder not found'}), 404
    
    folders = []
    files = []
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isdir(item_path):
            folders.append(item)
        else:
            files.append(item)
    
    return jsonify({'folders': folders, 'files': files})

@app.route('/dash/<username>/create_folder', methods=['POST'])
@login_required
def create_folder(username):
    if current_user.username != username:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if request.is_json:
        data = request.get_json()
        folder_name = data.get('folder_name')
        current_path = data.get('current_path', '').strip('/')
    else:
        folder_name = request.form.get('folder_name')
        current_path = request.form.get('current_path', '').strip('/')
    
    if not folder_name:
        return jsonify({'error': 'Folder name is required'}), 400
    
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], username, current_path, folder_name)
    
    if os.path.exists(folder_path):
        return jsonify({'error': 'Folder already exists'}), 400
    
    try:
        os.makedirs(folder_path)
        if request.is_json:
            return jsonify({'success': True, 'message': 'Folder created successfully'})
        else:
            flash(f"Folder '{folder_name}' created successfully.", 'success')
            return redirect(url_for('user_files', username=username, subpath=current_path))
    except Exception as e:
        if request.is_json:
            return jsonify({'error': str(e)}), 500
        else:
            flash(f"Error creating folder: {str(e)}", 'error')
            return redirect(url_for('user_files', username=username, subpath=current_path))

@app.route('/dash/<username>/rename', methods=['POST'])
@login_required
def rename_user_file(username):
    if current_user.username != username:
        return "Unauthorized", 401
    
    old_filename = request.form['old_filename']
    new_filename = secure_filename(request.form['new_filename'])
    item_type = request.form['item_type']
    current_path = request.form.get('current_path', '').rstrip('/')
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    full_current_path = os.path.join(user_folder, current_path)
    
    old_path = os.path.join(full_current_path, old_filename)
    new_path = os.path.join(full_current_path, new_filename)
    
    if not os.path.exists(old_path):
        flash(f"The {item_type} '{old_filename}' does not exist.", 'error')
        return redirect(url_for('user_files', username=username, subpath=current_path))
    
    try:
        os.rename(old_path, new_path)
        flash(f"Successfully renamed {item_type} from '{old_filename}' to '{new_filename}'.", 'success')
    except OSError as e:
        flash(f"Error renaming {item_type}: {str(e)}", 'error')
    
    return redirect(url_for('user_files', username=username, subpath=current_path))

@app.route('/upload/file', methods=['POST'])
def upload_file():
    app.logger.info("Starting upload_file function")
    
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    user_id = None
    
    if api_key:
        # If API key is provided, get user from database
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE api_key = ?", (api_key,))
        user = cursor.fetchone()
        if user:
            user_id = user[0]
    elif current_user.is_authenticated:
        # If no API key but user is logged in via web
        user_id = current_user.id
    
    app.logger.info(f"User ID determined: {user_id}")
    
    if 'file' not in request.files:
        app.logger.error("No file part in the request")
        return jsonify({'success': False, 'error': 'No file part'}), 400
    
    # Rest of your existing upload_file code...
    file = request.files['file']
    if file.filename == '':
        app.logger.error("No selected file")
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    
    if file:
        try:
            app.logger.info(f"Processing file: {file.filename}")
            filename = secure_filename(file.filename)
            extension = os.path.splitext(filename)[1].lower()
            vanity = shortuuid.uuid()[:8]
            vanity_with_extension = f"{vanity}{extension}"
            new_filename = vanity_with_extension
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], new_filename)
            
            file.save(file_path)
            app.logger.info("File saved successfully")
            
            password = request.form.get('password')
            is_private = 1 if password else 0
            
            db = get_db()
            cursor = db.cursor()
            
            # Use the determined user_id in the database insert
            cursor.execute("""
                INSERT INTO content (vanity, type, data, created_at, user_id, is_private, password) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (vanity_with_extension, 'file', new_filename, datetime.now(), user_id, is_private, password))
            
            db.commit()
            
            scheme = 'https' if request.is_secure else 'http'
            short_url = f"{scheme}://{request.host}/{vanity_with_extension}"
            download_url = f"{short_url}/download"
            
            response_data = {
                'success': True,
                'vanity': vanity_with_extension,
                'url': short_url,
                'download_url': download_url,
                'filename': new_filename
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            app.logger.error(f"Error uploading file: {str(e)}")
            app.logger.exception("Exception traceback:")
            return jsonify({'success': False, 'error': str(e)}), 500

    app.logger.error("Unknown error occurred")
    return jsonify({'success': False, 'error': 'Unknown error occurred'}), 500

# Add this function to validate passwords
def is_valid_password(password):
    banned_passwords = ['info', 'download']
    return password not in banned_passwords

@app.route('/reset_api_key', methods=['POST'])
@login_required
def reset_api_key():
    new_api_key = secrets.token_urlsafe(32)
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_api_key, current_user.id))
    db.commit()
    return jsonify({'success': True, 'new_api_key': new_api_key})

@app.route('/api/docs')
def api_docs():
    return render_template('api_docs.html')

@app.route('/dash')
@login_required
def dashboard():
    return redirect(url_for('user_files', username=current_user.username))

@app.route('/<vanity>/raw', methods=['GET', 'POST'])
@app.route('/<vanity>/raw/<password>', methods=['GET'])
def raw_vanity(vanity, password=None):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM content WHERE vanity = ?", (vanity,))
    content = cursor.fetchone()
    
    if content:
        content_type, content_data, created_at, user_id, is_private, stored_password = content[1], content[2], content[3], content[4], content[5], content[6]
        
        if is_private and stored_password:
            if password:
                if password != stored_password:
                    return "Incorrect password", 403
            elif request.method == 'POST':
                entered_password = request.form.get('password')
                if entered_password != stored_password:
                    return render_template('password_prompt.html', vanity=vanity, error="Incorrect password", raw=True)
            else:
                return render_template('password_prompt.html', vanity=vanity, error=None, raw=True)
        
        if content_type == 'pastebin':
            return content_data, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        elif content_type == 'file':
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], content_data)
            return send_file(file_path, as_attachment=True)
        elif content_type == 'url':
            return content_data, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    
    return 'Not Found', 404

if __name__ == '__main__':
    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=delete_old_files)
    cleanup_thread.daemon = True
    cleanup_thread.start()

    app.run(host='0.0.0.0', port=7122, debug=True)
