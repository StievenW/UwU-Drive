import random
from flask import (
    Flask, request, jsonify, send_file, render_template, 
    redirect, url_for, Response, session, make_response, g  # Add make_response and g here
)
import os
import sqlite3
import requests
import hashlib
from datetime import datetime
from io import BytesIO
import uuid
import json
from functools import wraps
import jwt
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hmac
import hashlib
from urllib.parse import urlparse
import base64
import tempfile
import os
from datetime import datetime, timedelta
import threading
import shutil
from werkzeug.middleware.proxy_fix import ProxyFix
import ssl
from flask_talisman import Talisman
from flask_cors import CORS
import re
import flask
from secrets import token_urlsafe
from pathlib import Path
from hashlib import sha256  # Add new import
from utils.file_merger import SafeFileMerger
from utils.webhook_manager import WebhookManager  # Add new import

# Add this class after the imports and before the app initialization
class PreviewCleanup:
    """Context manager for cleaning up preview files and tokens"""
    def __init__(self, token, temp_files=None):
        self.token = token
        self.temp_files = temp_files or []
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            # Cleanup temp files
            for temp_file in self.temp_files:
                if isinstance(temp_file, (str, Path)) and os.path.exists(temp_file):
                    try:
                        os.unlink(temp_file)
                    except Exception as e:
                        print(f"Error removing temp file {temp_file}: {e}")
            
            # Remove token data
            if self.token in TEMP_TOKENS:
                data = TEMP_TOKENS[self.token]
                # Clean up merged files if any
                if data.get('is_merged') and 'file_url' in data:
                    try:
                        if os.path.exists(data['file_url']):
                            os.unlink(data['file_url'])
                    except Exception as e:
                        print(f"Error removing merged file: {e}")
                del TEMP_TOKENS[self.token]
                
            if self.token in PREVIEW_TOKENS:
                del PREVIEW_TOKENS[self.token]
                
        except Exception as e:
            print(f"Error in preview cleanup: {e}")
        
        return False  # Don't suppress exceptions

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Add secret key for session

# Constants
DB_FILE = "file_metadata.db"
CHUNK_SIZE = 9.99 * 1024 * 1024  # Maximum 9MB per file as per Discord limit
JWT_SECRET = os.urandom(32)
SIGNATURE_SECRET = os.urandom(32)
TOKEN_EXPIRY = 3600  # 1 hour
WEBHOOK_TOKEN_SECRET = os.urandom(32)
WEBHOOK_TOKEN_EXPIRY = 3600  # 1 hour
TEMP_FILES_DIR = Path("temp_files")
TEMP_FILES_EXPIRE = 300  # 5 minutes
TEMP_TOKENS = {}
PREVIEW_TOKENS = {}

# Add after other global variables
WEBHOOK_FILE = "webhook_cdn.txt"
webhook_manager = WebhookManager(WEBHOOK_FILE)

# Create temp video directory if not exists
TEMP_FILES_DIR.mkdir(exist_ok=True)

# Fix Limiter initialization
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per day"], # Increase daily limit
    storage_uri="memory://"
)

# Security Configuration
ALLOWED_HOSTS = ['127.0.0.1']  # Ganti dengan domain Anda
CSRF_TIME_LIMIT = 3600  # 1 jam
PERMANENT_SESSION_LIFETIME = timedelta(days=1)
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

# Inisialisasi keamanan tambahan
app.config.update(
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=PERMANENT_SESSION_LIFETIME
)

# Setup CORS dengan pembatasan
CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_HOSTS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-Download-Token", "X-Chunk-Signature"]
    },
    # Tambahkan resource khusus untuk endpoint password dan delete
    r"/set_password": {
        "origins": ALLOWED_HOSTS,
        "methods": ["POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    },
    r"/delete": {
        "origins": ALLOWED_HOSTS,
        "methods": ["POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Tambahkan Talisman untuk header keamanan
talisman = Talisman(
    app,
    force_https=False,  # Tetap false karena menggunakan Cloudflare
    strict_transport_security=True,
    session_cookie_secure=True,
    feature_policy={
        'geolocation': '\'none\'',
        'midi': '\'none\'',
        'microphone': '\'none\'',
        'camera': '\'none\'',
        'magnetometer': '\'none\'',
        'gyroscope': '\'none\'',
        'accelerometer': '\'none\'',
        'payment': '\'none\'',
        'usb': '\'none\''
    },
    content_security_policy={
        'default-src': [
            '\'self\'',
            'https:', # Allow HTTPS resources
            'data:', # Allow data: URIs
            'ws:', # Allow WebSocket
            'wss:' # Allow Secure WebSocket
        ],
        'img-src': [
            '\'self\'',
            'data:',
            'https:',
            'cdn.discordapp.com',
            'cdnjs.cloudflare.com'
        ],
        'script-src': [
            '\'self\'',
            '\'unsafe-inline\'',
            '\'unsafe-eval\'',
            'cdn.jsdelivr.net',
            'cdnjs.cloudflare.com',
            'stackpath.bootstrapcdn.com'
        ],
        'style-src': [
            '\'self\'',
            '\'unsafe-inline\'',
            'cdn.jsdelivr.net',
            'cdnjs.cloudflare.com',
            'stackpath.bootstrapcdn.com',
            'fonts.googleapis.com'
        ],
        'font-src': [
            '\'self\'',
            'fonts.gstatic.com',
            'cdnjs.cloudflare.com',
            'data:'
        ],
        'connect-src': [
            '\'self\'',
            'https:',
            'wss:',
            'cdn.discordapp.com'
        ]
    }
)

# Middleware untuk validasi host
def validate_host(app):
    @app.before_request
    def before_request():
        if not request.host:
            return jsonify({"error": "Invalid host"}), 400
            
        host = request.host.split(':')[0]
        if host not in ALLOWED_HOSTS:
            return jsonify({"error": "Invalid host"}), 400

# Validasi input untuk semua request
def sanitize_input(data):
    if isinstance(data, str):
        # Hapus karakter berbahaya
        return re.sub(r'[<>\'\";&]', '', data)
    elif isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(x) for x in data]
    return data

@app.after_request
def remove_hop_by_hop_headers(response: Response):
    response.headers.pop("Connection", None)  # Hapus header Connection jika ada
    return response
    
@app.before_request
def validate_request():
    if request.method == 'POST':
        if request.is_json:
            # Simpan json yang sudah disanitasi ke dalam g object
            flask.g.json = sanitize_input(request.get_json())
        if request.form:
            request.form = sanitize_input(request.form.to_dict())
    if request.args:
        request.args = sanitize_input(request.args.to_dict())

# Tambahkan decorator untuk mengakses json yang sudah disanitasi
def get_sanitized_json():
    """Helper function untuk mengambil JSON yang sudah disanitasi"""
    return getattr(flask.g, 'json', None)

# Setup proxy support
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Setup database for storing file metadata
def migrate_urls():
    """Migrate URLs in the database to remove query parameters."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Select all URLs that contain query parameters
        cursor.execute("""
            SELECT id, file_url 
            FROM files 
            WHERE file_url LIKE '%?%'
        """)
        
        rows = cursor.fetchall()
        if not rows:
            print("No URLs to migrate.")
            return
        
        # Update each URL to remove query parameters
        for row in rows:
            file_id, file_url = row
            base_url = file_url.split('?')[0]
            cursor.execute("""
                UPDATE files 
                SET file_url = ? 
                WHERE id = ?
            """, (base_url, file_id))
        
        conn.commit()
        print(f"Migrated {len(rows)} URLs successfully.")
        
    except Exception as e:
        print(f"Error migrating URLs: {str(e)}")
    finally:
        conn.close()

def setup_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Add webhook_hash index to improve query performance
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            part_number INTEGER,
            file_url TEXT,
            file_hash TEXT,
            file_size INTEGER,
            upload_date TEXT,
            webhook_hash TEXT NOT NULL, -- Make webhook_hash required
            download_id TEXT,
            is_enabled BOOLEAN DEFAULT 1,
            password TEXT DEFAULT NULL,
            total_parts INTEGER DEFAULT NULL,
            is_complete BOOLEAN DEFAULT 0,
            is_chunk BOOLEAN DEFAULT 0,
            mime_type TEXT DEFAULT NULL,
            last_password_change TEXT DEFAULT NULL  -- Add column for tracking password changes
        )
    """)
    
    # Add index on webhook_hash
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_webhook_hash 
        ON files(webhook_hash)
    """)
    
    # Check if migration from webhook_url to webhook_hash is needed
    try:
        cursor.execute("SELECT webhook_url FROM files LIMIT 1")
        # If we get here, webhook_url column exists and needs migration
        print("Migrating webhook URLs to hashed format...")
        
        # Get all unique webhook URLs
        cursor.execute("SELECT DISTINCT webhook_url FROM files WHERE webhook_url IS NOT NULL")
        rows = cursor.fetchall()
        
        # Add webhook_hash column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE files ADD COLUMN webhook_hash TEXT")
        except sqlite3.OperationalError:
            # Column already exists
            pass
        
        # Update each row with SHA-256 hashed webhook URL
        for (webhook_url,) in rows:
            if webhook_url:
                webhook_hash = hash_webhook_url(webhook_url)
                cursor.execute("""
                    UPDATE files 
                    SET webhook_hash = ?
                    WHERE webhook_url = ?
                """, (webhook_hash, webhook_url))
        
        # Drop old webhook_url column
        cursor.execute("CREATE TABLE files_new AS SELECT * FROM files")
        cursor.execute("DROP TABLE files")
        cursor.execute("""
            CREATE TABLE files AS 
            SELECT id, filename, part_number, file_url, file_hash, 
                   file_size, upload_date, webhook_hash, download_id, 
                   is_enabled, password, total_parts, is_complete, is_chunk 
            FROM files_new
        """)
        cursor.execute("DROP TABLE files_new")
        
        print("Migration completed successfully")
        
    except sqlite3.OperationalError:
        # webhook_url column doesn't exist, no migration needed
        pass
    
    # Check if mime_type column exists
    try:
        cursor.execute("ALTER TABLE files ADD COLUMN mime_type TEXT")
    except sqlite3.OperationalError:
        pass # Column already exists
        
    # Add column for tracking password changes if not exists
    try:
        cursor.execute("ALTER TABLE files ADD COLUMN last_password_change TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists
        
    # Call the URL migration function
    migrate_urls()
    
    conn.commit()
    conn.close()

# Function to convert file size to a more readable format
def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            # Add .2f for 2 decimal places
            return '{:.2f} {}'.format(size, unit)
        size /= 1024.0  # Use 1024.0 for float division

# Add this global dictionary to store temporary chunks
temp_uploads = {}

# Add helper function for generating chunk names
def generate_chunk_name(part_number):
    secure_id = generate_file_id()
    return f"{secure_id}_{part_number}"

def generate_download_token(download_id, is_enabled, has_password, is_verified):
    return jwt.encode({
        'download_id': download_id,
        'is_enabled': is_enabled,
        'has_password': has_password,
        'is_verified': is_verified,
        'exp': time.time() + TOKEN_EXPIRY,
        'iat': time.time()
    }, JWT_SECRET, algorithm='HS256')

def generate_chunk_signature(download_id, chunk_number, token):
    message = f"{download_id}:{chunk_number}:{token}".encode()
    return hmac.new(SIGNATURE_SECRET, message, hashlib.sha256).hexdigest()

def verify_download_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-Download-Token')
        if not token:
            return jsonify({"error": "No download token provided"}), 401
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            download_id = kwargs.get('download_id')
            
            if payload['download_id'] != download_id:
                raise jwt.InvalidTokenError
                
            if not payload.get('is_enabled'):
                return jsonify({"error": "File access disabled"}), 403
                
            if payload.get('has_password') and not payload.get('is_verified'):
                return jsonify({"error": "Password verification required"}), 401
                
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Download token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid download token"}), 401
            
    return decorated_function

def generate_webhook_token(webhook_url):
    """Generate token untuk autentikasi webhook"""
    return jwt.encode({
        'webhook_url': webhook_url,
        'exp': time.time() + WEBHOOK_TOKEN_EXPIRY,
        'iat': time.time()
    }, WEBHOOK_TOKEN_SECRET, algorithm='HS256')

def verify_webhook_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-Webhook-Token')
        if not token:
            return jsonify({"error": "No webhook token provided"}), 401
        
        try:
            payload = jwt.decode(token, WEBHOOK_TOKEN_SECRET, algorithms=['HS256'])
            # Handle both GET and POST requests
            if request.method == 'GET':
                webhook_url = request.args.get('webhook_url')
            else:
                data = request.get_json()
                webhook_url = data.get('webhook_url') if data else None
            
            if not webhook_url or payload['webhook_url'] != webhook_url:
                raise jwt.InvalidTokenError
                
            return f(*args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Webhook token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid webhook token"}), 401
            
    return decorated_function

# Upload file with progress
def generate_file_id():
    """Generate a secure file ID using UUID v4 + Base64"""
    # Generate UUID v4 and combine with timestamp
    unique_str = f"{uuid.uuid4().hex}{int(time.time())}"
    
    # Generate SHA-256 hash
    hash_obj = hashlib.sha256(unique_str.encode())
    hash_val = hash_obj.digest()
    
    # Convert to URL-safe Base64 and remove padding
    file_id = base64.urlsafe_b64encode(hash_val).decode('utf-8').rstrip('=')
    
    # Take first 22 characters
    return file_id[:22]

def hash_webhook_url(webhook_url):
    """Hash webhook URL using plain SHA-256"""
    try:
        # Create SHA-256 hash directly from webhook URL
        hash_obj = hashlib.sha256(webhook_url.encode())
        # Return hex digest
        return hash_obj.hexdigest()
    except Exception as e:
        print(f"Error hashing webhook URL: {str(e)}")
        return None

def verify_webhook_hash(webhook_url, stored_hash):
    """Verify webhook URL against stored hash"""
    try:
        # Hash the provided webhook URL
        current_hash = hash_webhook_url(webhook_url)
        # Compare with stored hash
        return current_hash == stored_hash
    except Exception as e:
        print(f"Error verifying webhook hash: {str(e)}")
        return False

def create_temp_video_token(download_id, file_url, request_headers):
    """Create a temporary token with browser fingerprint"""
    # Create browser fingerprint from request headers
    fingerprint = sha256(json.dumps({
        'user_agent': request_headers.get('User-Agent', ''),
        'accept_language': request_headers.get('Accept-Language', ''),
        'accept_encoding': request_headers.get('Accept-Encoding', '')
    }, sort_keys=True).encode()).hexdigest()
    
    token = token_urlsafe(32)  # Increase token length for security
    expires = time.time() + TEMP_FILES_EXPIRE
    
    TEMP_TOKENS[token] = {
        'download_id': download_id,
        'file_url': file_url,
        'expires': expires,
        'created': time.time(),
        'fingerprint': fingerprint,
        'used': False  # Track if token has been used
    }
    return token

def cleanup_expired_tokens():
    """Remove expired temporary media tokens and files"""
    current_time = time.time()
    expired = []
    
    for token, data in TEMP_TOKENS.items():
        if current_time > data['expires']:
            expired.append(token)
            # Cleanup temporary files if they exist
            media_path = TEMP_FILES_DIR / f"{token}{data.get('extension', '')}"
            if media_path.exists():
                try:
                    media_path.unlink()
                except Exception as e:
                    print(f"Error cleaning up temp file: {e}")
    
    # Remove expired tokens
    for token in expired:
        TEMP_TOKENS.pop(token, None)

def create_preview_token(download_id, file_url, headers, is_enabled=True, has_password=False, is_verified=False):
    """Create one-time use preview token with security info"""
    preview_token = token_urlsafe(32)
    browser_id = create_browser_id(request)  # Use request object directly
    
    PREVIEW_TOKENS[preview_token] = {
        'download_id': download_id,
        'file_url': file_url,
        'browser_id': browser_id,
        'used': False,
        'created': time.time(),
        'expires': time.time() + 300,  # 5 minutes
        'is_enabled': is_enabled,
        'has_password': has_password,
        'is_verified': is_verified
    }
    return preview_token

def create_browser_id(request):
    """Create a unique browser identifier from request headers"""
    return sha256(json.dumps({
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'accept': request.headers.get('Accept', '')
    }, sort_keys=True).encode()).hexdigest()

def verify_browser_id(request, stored_id):
    """Verify browser identity matches stored ID"""
    current_id = create_browser_id(request)
    return hmac.compare_digest(current_id.encode(), stored_id.encode())

@app.route('/upload', methods=['POST'])
@limiter.limit("10/minute")  # Pindahkan rate limit ke sini
def upload_file():
    try:
        webhook_url = request.form.get('webhook_url')
        file = request.files['file']
        
        if not all([webhook_url, file]):
            return jsonify({"error": "Missing required parameters"}), 400

        # Generate secure file ID using the new method
        download_id = generate_file_id()
        
        filename = file.filename
        file_data = file.read()
        file_size = len(file_data)
        file.seek(0)
        
        # Check file size limit
        if file_size > CHUNK_SIZE:
            return jsonify({"error": "File too large. Please use chunked upload for files over 8MB"}), 413
        
        try:
            # Upload to Discord with proper headers
            files = {
                "file": (
                    filename,
                    file_data,
                    file.content_type or 'application/octet-stream'
                )
            }
            headers = {
                "User-Agent": "DiscordBot (Custom, 1.0)"
            }
            
            response = requests.post(webhook_url, files=files, headers=headers)

            # Detailed error handling
            if response.status_code != 200:
                error_msg = f"Discord API Error: {response.status_code}"
                try:
                    error_data = response.json()
                    if 'message' in error_data:
                        error_msg += f" - {error_data['message']}"
                except:
                    pass
                raise Exception(error_msg)

            # Get file URL from Discord response
            response_data = response.json()
            if not response_data.get("attachments"):
                raise Exception("No attachment data in Discord response")
                
            file_url = response_data["attachments"][0]["url"]
            webhook_hash = hash_webhook_url(webhook_url)
            
            # Save to database using the new secure download_id
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    INSERT INTO files (
                        filename, file_url, file_size, upload_date, 
                        webhook_hash, download_id, is_enabled, is_complete, is_chunk
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, 1, 0)
                """, (
                    filename,
                    file_url,
                    file_size,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    webhook_hash,
                    download_id
                ))
                
                conn.commit()
                
                # Return the new secure download ID
                return jsonify({
                    "status": "success",
                    "message": "File uploaded successfully",
                    "download_id": download_id,
                    "download_link": url_for('download_page', download_id=download_id, _external=True)
                }), 200
                
            except Exception as e:
                conn.rollback()
                raise Exception(f"Database error: {str(e)}")
            finally:
                conn.close()
                
        except requests.RequestException as e:
            raise Exception(f"Network error: {str(e)}")
            
    except Exception as e:
        print(f"Upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Add new class for managing uploads
class ChunkUpload:
    def __init__(self, filename, total_parts, webhook_url):
        self.filename = filename
        self.total_parts = total_parts
        self.webhook_url = webhook_url
        self.chunks = {}
        self.upload_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.total_size = 0
        self.complete = False

    def add_chunk(self, part_number, url, size):
        self.chunks[part_number] = {'url': url, 'size': size}
        self.total_size += size
        if len(self.chunks) == self.total_parts:
            self.complete = True

# Store uploads in memory
active_uploads = {}

# Add new function to manage temporary metadata
def save_file_metadata(upload_id, file_data):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Begin transaction
        conn.execute('BEGIN')
        
        try:
            # Check if all chunks are present and valid
            cursor.execute("""
                SELECT COUNT(*) as chunk_count,
                       COUNT(DISTINCT part_number) as unique_chunks,
                       MAX(part_number) as max_chunk,
                       MIN(part_number) as min_chunk
                FROM temp_chunks 
                WHERE upload_id = ?
            """, (upload_id,))
            
            result = cursor.fetchone()
            chunk_count, unique_chunks, max_chunk, min_chunk = result
            
            # Verify chunk sequence integrity
            if (chunk_count != file_data['total_parts'] or 
                unique_chunks != file_data['total_parts'] or
                max_chunk != file_data['total_parts'] - 1 or
                min_chunk != 0):
                raise Exception("Incomplete or invalid chunk sequence")

            # Move data from temp_chunks to files table
            cursor.execute("""
                INSERT INTO files 
                (filename, part_number, file_url, upload_date, webhook_url, 
                 download_id, is_enabled, file_size, total_parts, is_complete)
                SELECT 
                    ?, part_number, file_url, ?, ?, ?, 1, ?, ?, 1
                FROM temp_chunks 
                WHERE upload_id = ?
                ORDER BY part_number
            """, (
                file_data['filename'],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                file_data['webhook_url'],
                file_data['download_id'],
                file_data['total_size'],
                file_data['total_parts'],
                upload_id
            ))

            # Delete from temp_chunks
            cursor.execute("DELETE FROM temp_chunks WHERE upload_id = ?", (upload_id,))
            
            # Commit transaction
            conn.commit()
            return True
            
        except Exception as e:
            conn.rollback()
            print(f"Error saving metadata: {str(e)}")
            return False
            
        finally:
            conn.close()
            
    except Exception as e:
        print(f"Database error: {str(e)}")
        return False

# Update upload_chunk route to only store temporary data
@app.route('/upload_chunk', methods=['POST'])
@limiter.limit("120 per minute")
def upload_chunk():
    try:
        webhook_url = request.form.get('webhook_url')
        file = request.files.get('file')
        upload_id = request.form.get('upload_id')
        embed = request.form.get('embed')
        mime_type = request.form.get('mime_type')
        
        if not upload_id:
            # Selalu generate ID baru menggunakan format secure
            upload_id = generate_file_id()
            
        part_number = int(request.form.get('part_number'))
        total_parts = int(request.form.get('total_parts'))
        filename = request.form.get('filename')
        chunk_size = int(request.form.get('chunk_size', 0))

        if not all([webhook_url, file, upload_id, filename]):
            return jsonify({"error": "Missing required parameters"}), 400

        try:
            # Generate nama chunk dengan ID yang aman
            chunk_filename = generate_chunk_name(part_number)
            files = {
                "file": (chunk_filename, file.stream, mime_type or 'application/octet-stream')
            }
            headers = {"User-Agent": "DiscordBot (Custom, 1.0)"}
            
            # Add embed if provided
            payload = {}
            if embed:
                payload = json.loads(embed)
            
            # Send to Discord with embed
            response = requests.post(
                webhook_url, 
                files=files,
                json=payload,
                headers={"User-Agent": "DiscordBot (UwU Drive, 1.0)"}
            )
            if response.status_code != 200:
                return jsonify({"error": f"Discord API Error: {response.status_code}"}), 500

            data = response.json()
            if not data.get("attachments"):
                return jsonify({"error": "No attachment in Discord response"}), 500
                
            file_url = data["attachments"][0]["url"]
            # Strip query parameters from the file URL
            file_url = file_url.split('?')[0]
            webhook_hash = hash_webhook_url(webhook_url)

            # Store chunk metadata with secure ID and mime_type
            if upload_id not in temp_uploads:
                temp_uploads[upload_id] = {
                    'chunks': {},
                    'metadata': {
                        'filename': filename,
                        'total_parts': total_parts,
                        'upload_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'secure_id': upload_id,  # Store the secure ID
                        'webhook_hash': webhook_hash,  # Store hash instead of URL
                        'mime_type': mime_type
                    }
                }

            temp_uploads[upload_id]['chunks'][part_number] = {
                'url': file_url,
                'size': chunk_size
            }

            return jsonify({
                "success": True,
                "chunk_number": part_number,
                "file_url": file_url,
                "chunk_size": chunk_size,
                "secure_id": upload_id  # Return secure ID in response
            })

        except requests.RequestException as e:
            return jsonify({"error": f"Discord API error: {str(e)}"}), 500

    except Exception as e:
        print(f"Upload chunk error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Add new route for completing upload
@app.route('/complete_upload', methods=['POST'])
def complete_upload():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        required_fields = ['upload_id', 'filename', 'webhook_url', 'chunks', 'total_size']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        webhook_hash = hash_webhook_url(data['webhook_url'])
        if not webhook_hash:
            return jsonify({"error": "Invalid webhook URL"}), 400

        # Generate secure ID baru untuk file lengkap
        secure_download_id = generate_file_id()
        
        chunks = data['chunks']
        if not chunks or not isinstance(chunks, list):
            return jsonify({"error": "Invalid chunks data"}), 400

        # Verify total size matches sum of chunks
        total_chunk_size = sum(chunk['chunk_size'] for chunk in chunks)
        if total_chunk_size != data['total_size']:
            return jsonify({"error": "Size mismatch"}), 400

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        try:
            cursor.execute('BEGIN')

            # Insert main file record with secure ID
            cursor.execute("""
                INSERT INTO files (
                    filename, file_url, file_size, upload_date,
                    webhook_hash, download_id, is_enabled,
                    total_parts, is_complete, is_chunk, mime_type
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1, 0, ?)
            """, (
                data['filename'],
                chunks[0]['file_url'],
                data['total_size'],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                webhook_hash,  # Use webhook_hash instead of webhook_url
                secure_download_id,  # Use new secure ID
                len(chunks),
                data.get('mime_type', 'application/octet-stream')
            ))

            # Insert chunks with same secure ID
            for chunk in chunks:
                cursor.execute("""
                    INSERT INTO files (
                        filename, part_number, file_url, file_size,
                        upload_date, webhook_hash, download_id,
                        is_enabled, total_parts, is_complete,
                        is_chunk, mime_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1, 1, ?)
                """, (
                    chunk.get('original_name', f"{data['filename']}.part{chunk['chunk_number']}"),
                    chunk['chunk_number'],
                    chunk['file_url'],
                    chunk['chunk_size'],
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    webhook_hash,  # Use webhook_hash instead of webhook_url
                    secure_download_id,  # Use same secure ID for chunks
                    len(chunks),
                    data.get('mime_type', 'application/octet-stream')
                ))

            conn.commit()

            # Clean up temporary data
            if data['upload_id'] in temp_uploads:
                del temp_uploads[data['upload_id']]

            return jsonify({
                "success": True,
                "download_id": secure_download_id,
                "download_link": url_for('download_page', download_id=secure_download_id, _external=True),
                "message": "Upload completed successfully"
            })

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    except Exception as e:
        print(f"Complete upload error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Add cleanup function for temporary chunks
@app.route('/cleanup_temp_chunks', methods=['POST'])
def cleanup_temp_chunks():
    try:
        upload_id = request.json.get('upload_id')
        if not upload_id:
            return jsonify({"error": "Upload ID required"}), 400

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM temp_chunks WHERE upload_id = ?", (upload_id,))
        conn.commit()
        conn.close()

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def save_complete_upload(upload):
    try:
        # Change from uuid to secure file ID
        download_id = generate_file_id()
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        try:
            for part_num, chunk_data in upload.chunks.items():
                cursor.execute("""
                    INSERT INTO files 
                    (filename, part_number, file_url, file_size, upload_date, 
                     webhook_url, download_id, is_enabled) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """, (
                    upload.filename,
                    part_num,
                    chunk_data['url'],
                    upload.total_size,
                    upload.upload_date,
                    upload.webhook_url,
                    download_id
                ))
            
            conn.commit()
            del active_uploads[upload.upload_id]
            
            return jsonify({
                "success": True,
                "complete": True,
                "download_id": download_id,
                "download_link": url_for('download_page', download_id=download_id, _external=True),
                "total_size": upload.total_size
            })
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    except Exception as e:
        print(f"Error saving complete upload: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/cancel_upload', methods=['POST'])
def cancel_upload():
    try:
        data = request.get_json()
        upload_id = data.get('upload_id')
        
        if not upload_id:
            return jsonify({"error": "Upload ID not provided"}), 400

        # Cleanup active uploads
        if upload_id in active_uploads:
            del active_uploads[upload_id]
        
        # Also cleanup temp uploads if exist
        if upload_id in temp_uploads:
            del temp_uploads[upload_id]
        
        return jsonify({
            "status": "success",
            "message": "Upload cancelled successfully"
        }), 200

    except Exception as e:
        print(f"Error in cancel_upload: {str(e)}")
        return jsonify({
            "status": "success",
            "message": "Upload cancelled"
        }), 200

# Add cleanup function for old temporary uploads
def cleanup_old_temp_uploads():
    current_time = datetime.now()
    to_remove = []
    for upload_id, data in temp_uploads.items():
        upload_time = datetime.strptime(data['metadata']['upload_date'], "%Y-%m-%d %H:%M:%S")
        if (current_time - upload_time).seconds > 3600:  # Remove after 1 hour
            to_remove.append(upload_id)
    for upload_id in to_remove:
        del temp_uploads[upload_id]

# Add this to your existing routes
@app.route('/upload_status/<upload_id>', methods=['GET'])
def check_upload_status(upload_id):
    if upload_id in temp_uploads:
        chunks_received = len(temp_uploads[upload_id]['chunks'])
        total_parts = temp_uploads[upload_id]['metadata']['total_parts']
        return jsonify({
            "status": "in_progress",
            "chunks_received": chunks_received,
            "total_parts": total_parts
        })
    return jsonify({"status": "not_found"}), 404

# Fetch file details by download ID
@app.route('/file/details/<download_id>', methods=['GET'])
@limiter.limit("30/minute")
def fetch_file_details(download_id):
    try:
        # No longer require webhook URL for viewing file details
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT filename, file_size, upload_date, is_enabled, 
                   CASE WHEN password IS NULL THEN 0 ELSE 1 END as has_password,
                   mime_type
            FROM files 
            WHERE download_id = ? 
            AND is_chunk = 0
            LIMIT 1
        """, (download_id,))
        
        file = cursor.fetchone()
        conn.close()

        if not file:
            return jsonify({"error": "File not found"}), 404

        # Generate initial download token
        is_verified = session.get(f'verified_{download_id}', False)
        token = generate_download_token(
            download_id,
            bool(file[3]),  # is_enabled
            bool(file[4]),  # has_password
            is_verified
        )

        return jsonify({
            "filename": file[0],
            "file_size": format_size(file[1]),
            "upload_date": file[2],
            "is_enabled": bool(file[3]),
            "has_password": bool(file[4]),
            "mime_type": file[5],
            "download_token": token
        }), 200
        
    except Exception as e:
        print(f"Error fetching file details: {str(e)}")
        return jsonify({"error": "Failed to fetch file details"}), 500

@app.route('/delete', methods=['POST', 'OPTIONS'])
def delete_file():
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response

    try:
        filename = request.form.get('filename')
        webhook_url = request.form.get('webhook_url')
        download_id = request.form.get('download_id')
        
        if not all([filename, webhook_url, download_id]):
            return jsonify({
                "error": "Missing required parameters",
                "details": {
                    "filename": bool(filename),
                    "webhook_url": bool(webhook_url),
                    "download_id": bool(download_id)
                }
            }), 400

        # Get webhook hash
        webhook_hash = hash_webhook_url(webhook_url)
        if not webhook_hash:
            return jsonify({"error": "Invalid webhook URL"}), 400

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            # First check if file exists with this download_id
            cursor.execute("""
                SELECT id 
                FROM files 
                WHERE download_id = ? 
                AND is_chunk = 0
                LIMIT 1
            """, (download_id,))
            
            result = cursor.fetchone()
            if not result:
                return jsonify({"error": "File not found"}), 404

            # Delete all related records
            cursor.execute("""
                DELETE FROM files 
                WHERE download_id = ?
            """, (download_id,))
            
            conn.commit()
            
            return jsonify({
                "status": "success",
                "message": f"File {filename} deleted successfully"
            }), 200
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
            
    except Exception as e:
        print(f"Delete error: {str(e)}")
        return jsonify({
            "error": "Failed to delete file",
            "message": str(e)
        }), 500

@app.route('/files', methods=['POST'])
@verify_webhook_token
def refresh_file_list():
    try:
        json_data = get_sanitized_json() or request.get_json()
        if not json_data or 'webhook_url' not in json_data:
            return jsonify({"error": "Webhook URL not provided"}), 400
        
        webhook_url = json_data.get('webhook_url')
        webhook_hash = hash_webhook_url(webhook_url)

        if not webhook_hash:
            return jsonify({"error": "Invalid webhook URL"}), 400
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Modified query to only return files matching webhook_hash
        cursor.execute("""
            SELECT DISTINCT
                filename,
                file_size,
                upload_date,
                download_id,
                is_enabled,
                CASE WHEN password IS NULL THEN 0 ELSE 1 END as has_password
            FROM files 
            WHERE webhook_hash = ?
            AND is_chunk = 0 
            AND is_complete = 1
            ORDER BY upload_date DESC
        """, (webhook_hash,))
        
        files = [{
            "filename": row[0],
            "file_size": format_size(row[1]) if row[1] else '0 B',
            "upload_date": row[2],
            "download_id": row[3],
            "is_enabled": bool(row[4]),
            "has_password": bool(row[5])
        } for row in cursor.fetchall() if row[0]]  # Only include files with names
        
        conn.close()
        
        return jsonify({
            "files": files,
            "total_files": len(files)
        }), 200
        
    except Exception as e:
        print(f"Error in refresh_file_list: {str(e)}")
        return jsonify({
            "error": "Failed to load files",
            "message": str(e)
        }), 500

# Serve the main page
@app.route('/')
def index():
    return render_template('index.html')

# Add new routes for security features
@app.route('/toggle_file', methods=['POST'])
def toggle_file():
    try:
        download_id = request.form.get('download_id')
        webhook_url = request.form.get('webhook_url')
        
        if not all([download_id, webhook_url]):
            return jsonify({"error": "Required parameters missing"}), 400

        webhook_hash = hash_webhook_url(webhook_url)
        if not webhook_hash:
            return jsonify({"error": "Invalid webhook URL"}), 400

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            # First check if file exists with this download_id
            cursor.execute("""
                SELECT id, is_enabled 
                FROM files 
                WHERE download_id = ? 
                AND is_chunk = 0
                LIMIT 1
            """, (download_id,))
            
            result = cursor.fetchone()
            if not result:
                return jsonify({"error": "File not found"}), 404
            
            file_id, current_state = result
            new_state = not bool(current_state)

            # Update all records for this download_id
            cursor.execute("""
                UPDATE files 
                SET is_enabled = ?
                WHERE download_id = ?
            """, (int(new_state), download_id))
            
            conn.commit()
            
            return jsonify({
                "status": "success",
                "is_enabled": new_state,
                "message": "Access " + ("enabled" if new_state else "disabled")
            })
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
            
    except Exception as e:
        print(f"Toggle file error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/set_password', methods=['POST', 'OPTIONS'])
def set_password():
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response

    try:
        download_id = request.form.get('download_id')
        webhook_url = request.form.get('webhook_url')
        password = request.form.get('password')
        
        if not all([download_id, webhook_url]):
            return jsonify({"error": "Required parameters missing"}), 400

        webhook_hash = hash_webhook_url(webhook_url)
        if not webhook_hash:
            return jsonify({"error": "Invalid webhook URL"}), 400

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            # Update password and set change timestamp
            cursor.execute("""
                UPDATE files 
                SET password = ?,
                    last_password_change = ?
                WHERE download_id = ?
            """, (
                password if password else None,
                time.time(),  # Track when password was changed
                download_id
            ))
            
            if cursor.rowcount == 0:
                conn.close()
                return jsonify({"error": "File not found"}), 404
            
            # Get updated password status
            cursor.execute("""
                SELECT COUNT(*) 
                FROM files 
                WHERE download_id = ? 
                AND password IS NOT NULL
            """, (download_id,))
            
            has_password = cursor.fetchone()[0] > 0
            conn.commit()
            
            return jsonify({
                "status": "success",
                "has_password": has_password,
                "message": "Password removed" if not password else "Password set successfully"
            })
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
            
    except Exception as e:
        print(f"Set password error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/verify_password', methods=['POST'])
@limiter.limit("5/minute")  # Pindahkan rate limit ke sini
def verify_password():
    try:
        json_data = get_sanitized_json() or request.get_json()
        if not json_data:
            return jsonify({"error": "No data provided"}), 400
            
        download_id = json_data.get('download_id')
        password = json_data.get('password')
        
        if not all([download_id, password]):
            return jsonify({"error": "Required parameters missing"}), 400

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT password, is_enabled 
            FROM files 
            WHERE download_id = ? 
            AND (is_chunk = 0 OR is_chunk IS NULL)
            LIMIT 1
        """, (download_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({"error": "File not found"}), 404
            
        db_password, is_enabled = result
        
        # Check file access first
        if not is_enabled:
            return jsonify({
                "error": "File is disabled",
                "code": "FILE_DISABLED"
            }), 403
            
        # Verify password and update session
        if db_password != password:
            session[f'verified_{download_id}'] = False
            return jsonify({"verified": False}), 401
        
        # Set verified in session
        session[f'verified_{download_id}'] = True
        session.modified = True

        return jsonify({
            "verified": True,
            "message": "Password verified successfully"
        })
        
    except Exception as e:
        print(f"Password verification error: {str(e)}")
        return jsonify({"error": "Verification failed"}), 500

# Add new route for download page
@app.route('/file/d/<download_id>')
def download_page(download_id):
    return render_template('download.html')

# Add new route for fetching chunk information
@app.route('/file/chunks/<download_id>', methods=['GET'])
@verify_download_token
def get_chunk_info(download_id):
    try:
        token = request.headers.get('X-Download-Token')
        if not token:
            return jsonify({"error": "Missing download token"}), 401

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get main file info without webhook check
        cursor.execute("""
            SELECT filename, file_size, total_parts, is_enabled,
                   CASE WHEN password IS NULL THEN 0 ELSE 1 END as has_password
            FROM files 
            WHERE download_id = ? AND is_chunk = 0
            LIMIT 1
        """, (download_id,))
        
        file_info = cursor.fetchone()
        if not file_info:
            return jsonify({"error": "File not found"}), 404
            
        filename, total_size, total_parts, is_enabled, has_password = file_info
        
        # Security checks
        if not is_enabled:
            return jsonify({"error": "File is disabled"}), 403
        if has_password and not session.get(f'verified_{download_id}'):
            return jsonify({"error": "Password required"}), 401
        
        # Get chunk information without webhook check
        cursor.execute("""
            SELECT 
                part_number,
                file_url,
                file_size,
                file_hash,
                filename
            FROM files 
            WHERE download_id = ? AND is_chunk = 1
            ORDER BY part_number ASC
        """, (download_id,))
        
        chunks = []
        total_chunk_size = 0
        for row in cursor.fetchall():
            chunk_size = row[2] or 0  # Use 0 if size is NULL
            total_chunk_size += chunk_size
            chunks.append({
                "part": row[0],
                "url": row[1],
                "size": chunk_size,
                "hash": row[3],
                "name": row[4]
            })
        
        # Verify chunk consistency
        if len(chunks) != total_parts:
            return jsonify({"error": "Incomplete chunks"}), 500
            
        if total_chunk_size != total_size:
            return jsonify({"error": "Size mismatch"}), 500
        
        # Add signatures
        for chunk in chunks:
            chunk['signature'] = generate_chunk_signature(download_id, chunk['part'], token)
        
        response = jsonify({
            "success": True,
            "filename": filename,
            "total_size": total_size,
            "total_parts": total_parts,
            "chunks": chunks
        })
        
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        return response
        
    except Exception as e:
        print(f"Error getting chunk info: {str(e)}")
        return jsonify({"error": "Failed to get file chunks"}), 500

# Konstanta untuk temp file management
TEMP_DIR = os.path.join(tempfile.gettempdir(), 'uwudrive_chunks')
CHUNK_EXPIRY = 3600  # 1 jam dalam detik
CLEANUP_INTERVAL = 300  # 5 menit dalam detik

# Buat direktori temp jika belum ada
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR)

# Track chunk yang sedang diproses
active_downloads = {}
chunk_locks = {}

class ChunkTracker:
    def __init__(self):
        self.chunks = {}
        self.lock = threading.Lock()
        
    def add_chunk(self, download_id, chunk_number, temp_path):
        with self.lock:
            if download_id not in self.chunks:
                self.chunks[download_id] = {}
            self.chunks[download_id][chunk_number] = {
                'path': temp_path,
                'timestamp': datetime.now(),
                'sent': False
            }
    
    def mark_as_sent(self, download_id, chunk_number):
        with self.lock:
            if download_id in self.chunks and chunk_number in self.chunks[download_id]:
                self.chunks[download_id][chunk_number]['sent'] = True
                # Hapus chunk yang sudah terkirim
                temp_path = self.chunks[download_id][chunk_number]['path']
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                del self.chunks[download_id][chunk_number]
                
                # Hapus download_id jika semua chunk sudah terkirim
                if not self.chunks[download_id]:
                    del self.chunks[download_id]
    
    def cleanup_expired(self):
        with self.lock:
            now = datetime.now()
            expired = []
            for download_id in self.chunks:
                for chunk_number, info in list(self.chunks[download_id].items()):
                    if (now - info['timestamp']).seconds > CHUNK_EXPIRY:
                        if os.path.exists(info['path']):
                            os.remove(info['path'])
                        expired.append((download_id, chunk_number))
            
            # Hapus chunk yang expired
            for download_id, chunk_number in expired:
                if download_id in self.chunks and chunk_number in self.chunks[download_id]:
                    del self.chunks[download_id][chunk_number]
                if download_id in self.chunks and not self.chunks[download_id]:
                    del self.chunks[download_id]

chunk_tracker = ChunkTracker()

def start_cleanup_thread():
    def cleanup_task():
        while True:
            chunk_tracker.cleanup_expired()
            time.sleep(CLEANUP_INTERVAL)
    
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()

def refresh_cdn_links(file_url):
    """Send a new webhook request to refresh CDN links and return the updated URL."""
    try:
        # Generate or get session ID from current request context
        if not hasattr(g, 'session_id'):
            g.session_id = str(uuid.uuid4())

        # Get available webhook for this session
        webhook_url = webhook_manager.get_available_webhook(g.session_id)
        if not webhook_url:
            print("No webhooks available")
            return None

        # Prepare payload with link as embed image
        payload = {
            "embeds": [{
                "title": "Media Refresh",
                "description": "Refreshing CDN link",
                "image": {
                    "url": file_url
                }
            }]
        }

        # Send request to webhook
        response = requests.post(
            webhook_url,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DiscordBot (UwU Drive, 1.0)"
            }
        )

        if response.status_code == 200:
            data = response.json()
            # Get attachment data from embed
            if data.get("embeds") and data["embeds"][0].get("image"):
                image_data = data["embeds"][0]["image"]
                url = image_data.get("url")
                if not url.startswith("http"):
                    url = "https://" + url
                return url
        else:
            # If rate limited or error, release webhook so others can use it
            webhook_manager.release_webhook(webhook_url, g.session_id)

        raise Exception(f"Discord API Error: {response.status_code}")

    except Exception as e:
        print(f"Error refreshing CDN link: {str(e)}")
        return None

class SafeChunkStreamer:
    def __init__(self, temp_path, download_id, chunk_number):
        self.temp_path = temp_path
        self.download_id = download_id
        self.chunk_number = chunk_number
        self.file = None
        self.closed = False
        self.fully_sent = False
        
    def generate(self):
        try:
            self.file = open(self.temp_path, 'rb')
            while True:
                data = self.file.read(8192)
                if not data:
                    self.fully_sent = True  # Mark as fully sent when complete
                    break
                try:
                    yield data
                except (GeneratorExit, ConnectionAbortedError):
                    print(f"Client disconnected while streaming chunk {self.chunk_number}")
                    return
        except Exception as e:
            print(f"Error streaming chunk: {str(e)}")
            raise
        finally:
            self.cleanup()
            
    def cleanup(self):
        if not self.closed:
            self.closed = True
            if self.file:
                try:
                    self.file.close()
                except Exception as e:
                    print(f"Error closing file: {e}")
            
            # Only remove temp file if fully sent
            if self.fully_sent:
                try:
                    if os.path.exists(self.temp_path):
                        os.unlink(self.temp_path)
                        print(f"Removed temp file after successful transfer: {self.temp_path}")
                except Exception as e:
                    print(f"Error removing temp file: {e}")

def verify_download_session(download_id, token):
    """Verify download session is still valid even if password changes"""
    try:
        # Decode token tanpa verifikasi signature dulu
        payload = jwt.decode(token, options={"verify_signature": False})
        token_time = payload.get('iat', 0)
        
        # Get password change time from database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT last_password_change 
            FROM files 
            WHERE download_id = ? 
            AND is_chunk = 0
            LIMIT 1
        """, (download_id,))
        result = cursor.fetchone()
        conn.close()

        if not result or not result[0]:
            return True  # No password changes recorded
            
        # Check if token was issued before password change
        password_change_time = float(result[0])
        return token_time > password_change_time
        
    except Exception as e:
        print(f"Session verification error: {str(e)}")
        return False

@app.route('/proxy_chunk/<download_id>/<int:chunk_number>')
@verify_download_token
@limiter.limit("100 per minute", exempt_when=lambda: request.headers.get('X-Download-Resume') == 'true')
def proxy_chunk(download_id, chunk_number):
    token = request.headers.get('X-Download-Token')
    
    # Verify download session is still valid
    if not verify_download_session(download_id, token):
        return jsonify({
            "error": "Download session expired due to password change",
            "code": "SESSION_EXPIRED"
        }), 401

    temp_chunk_path = None
    headers = {
        'Content-Type': 'application/octet-stream',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Connection': 'close'
    }
    
    try:
        # Check if this is a resumed download
        is_resume = request.headers.get('X-Download-Resume') == 'true'
        
        # Add throttling counter to global state
        if not hasattr(g, 'chunk_downloads'):
            g.chunk_downloads = {}
            
        signature = request.headers.get('X-Chunk-Signature')
        token = request.headers.get('X-Download-Token')
        
        if not signature:
            return jsonify({"error": "Missing chunk signature"}), 401
            
        expected_signature = generate_chunk_signature(download_id, chunk_number, token)
        if not hmac.compare_digest(signature, expected_signature):
            return jsonify({"error": "Invalid chunk signature"}), 401

        # Get chunk URL from database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT file_url, is_enabled, webhook_hash,
                   CASE WHEN password IS NOT NULL THEN 1 ELSE 0 END as has_password
            FROM files 
            WHERE download_id = ? AND part_number = ?
        """, (download_id, chunk_number))
        
        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({"error": "Chunk not found"}), 404

        url, is_enabled, webhook_hash, has_password = result
        
        # Reset counter after 60 seconds
        current_time = time.time()
        if download_id in g.chunk_downloads:
            last_time, count = g.chunk_downloads[download_id]
            if current_time - last_time > 60:
                count = 0
        else:
            count = 0
            
        # Update counter
        g.chunk_downloads[download_id] = (current_time, count + 1)
        
        # Add retry logic
        retry_count = 0
        max_retries = 3

        # Verify access
        if not is_enabled:
            return jsonify({"error": "File is disabled"}), 403
        if has_password and not session.get(f'verified_{download_id}'):
            return jsonify({"error": "Password required"}), 401

        # Refresh CDN link if expired
        refreshed_url = refresh_cdn_links(url)
        if not refreshed_url:
            return jsonify({"error": "Failed to refresh CDN link"}), 500
            
        while retry_count < max_retries:
            try:
                # Get temp file path
                temp_chunk_path = os.path.join(TEMP_DIR, f"{download_id}_{chunk_number}.tmp")
                
                # Check if temp file already exists and is valid
                if os.path.exists(temp_chunk_path):
                    if os.path.getsize(temp_chunk_path) > 0:
                        print(f"Using existing temp file for chunk {chunk_number}")
                        streamer = SafeChunkStreamer(temp_chunk_path, download_id, chunk_number)
                        headers['X-Retry-Count'] = str(retry_count)
                        return Response(streamer.generate(), headers=headers, direct_passthrough=True)

                # Download chunk with timeout
                with requests.get(refreshed_url, stream=True, timeout=30) as discord_response:
                    discord_response.raise_for_status()
                    with open(temp_chunk_path, 'wb') as f:
                        for chunk in discord_response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)

                # Verify downloaded file
                if os.path.getsize(temp_chunk_path) > 0:
                    streamer = SafeChunkStreamer(temp_chunk_path, download_id, chunk_number)
                    headers['X-Retry-Count'] = str(retry_count)
                    return Response(streamer.generate(), headers=headers, direct_passthrough=True)
                else:
                    raise Exception("Downloaded chunk is empty")

            except Exception as e:
                print(f"Download attempt {retry_count + 1} failed: {str(e)}")
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(1)  # Wait before retry
                    continue
                raise  # Re-raise the last exception if all retries failed

        return jsonify({"error": "Failed to download chunk after retries"}), 500

    except Exception as e:
        print(f"Proxy error: {str(e)}")
        return jsonify({
            "error": "Failed to proxy chunk", 
            "retry": True,
            "message": str(e)
        }), 500

# Add new route for download file content
@app.route('/file/d/<download_id>/download', methods=['GET'])
def download_file_content(download_id):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get file metadata with corrected query
        cursor.execute("""
            SELECT 
                filename, 
                MIN(file_size) as total_size,  -- Changed from SUM to MIN
                COUNT(*) as total_parts,
                MIN(is_enabled) as is_enabled,
                MAX(CASE WHEN password IS NOT NULL THEN 1 ELSE 0 END) as has_password
            FROM files 
            WHERE download_id = ?
            GROUP BY download_id
        """, (download_id,))
        
        file_info = cursor.fetchone()
        if not file_info:
            conn.close()
            return jsonify({"error": "File not found"}), 404
        
        filename, total_size, total_parts, is_enabled, has_password = file_info
        
        # Security checks
        if not is_enabled:
            conn.close()
            return jsonify({
                "error": "Access Denied",
                "message": "This file has been disabled by the owner",
                "code": "FILE_DISABLED"
            }), 403
        
        if has_password and not session.get('verified_' + download_id):  # Fixed syntax
            conn.close()
            return jsonify({
                "error": "Access Denied",
                "message": "Password verification required",
                "code": "PASSWORD_REQUIRED"
            }), 403
        
        # Get chunks in order
        cursor.execute("""
            SELECT file_url, file_size 
            FROM files 
            WHERE download_id = ? 
            ORDER BY part_number ASC
        """, (download_id,))
        
        parts = cursor.fetchall()
        conn.close()

        def generate():
            file_content = BytesIO()
            downloaded_size = 0
            
            for i, (url, chunk_size) in enumerate(parts):
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        chunk_data = response.content
                        file_content.write(chunk_data)
                        downloaded_size += len(chunk_data)
                        
                        # Send progress update as JSON
                        progress = {
                            "current_chunk": i + 1,
                            "total_chunks": total_parts,
                            "downloaded_size": downloaded_size,
                            "total_size": total_size,
                            "progress": (downloaded_size / total_size) * 100
                        }
                        yield f"data: {json.dumps(progress)}\n\n"
                    else:
                        yield f"data: error\n\n"
                        return
                except Exception as e:
                    print(f"Error downloading chunk {i}: {str(e)}")
                    yield f"data: error\n\n"
                    return
            
            # After all chunks are assembled, send the file
            file_content.seek(0)
            yield file_content.getvalue()

        headers = {
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type': 'application/octet-stream',
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
        
        return Response(generate(), headers=headers)

    except Exception as e:
        print(f"Download error: {str(e)}")
        return jsonify({"error": "Download failed"}), 500

@app.route('/search_files', methods=['POST'])
@verify_webhook_token 
def search_files():
    try:
        data = request.get_json()
        if not data or 'webhook_url' not in data:
            return jsonify({"error": "Webhook URL not provided"}), 400
            
        webhook_url = data.get('webhook_url')
        search_term = data.get('search_term', '').strip().lower()
        
        # Get webhook hash
        webhook_hash = hash_webhook_url(webhook_url)
        if not webhook_hash:
            return jsonify({"error": "Invalid webhook URL"}), 400
            
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        try:
            # Modified query to include webhook_hash filter
            cursor.execute("""
                SELECT
                    filename,
                    file_size,
                    upload_date,
                    download_id,
                    is_enabled,
                    CASE WHEN password IS NULL THEN 0 ELSE 1 END as has_password
                FROM files 
                WHERE webhook_hash = ?
                AND is_chunk = 0 
                AND is_complete = 1 
                ORDER BY upload_date DESC
            """, (webhook_hash,))
            
            files = []
            for row in cursor.fetchall():
                if not row[0]:  # Skip if no filename
                    continue
                    
                # Manual case-insensitive search
                if search_term and search_term not in row[0].lower():
                    continue
                    
                files.append({
                    "filename": row[0],
                    "file_size": format_size(row[1]) if row[1] else '0 B',
                    "upload_date": row[2],
                    "download_id": row[3],
                    "is_enabled": bool(row[4]),
                    "has_password": bool(row[5])
                })

            
            return jsonify({"files": files, "total_files": len(files)}), 200

        finally:
            conn.close()
            
    except Exception as e:
        print(f"Search error: {str(e)}")
        return jsonify({"error": "Search failed", "message": str(e)}), 500

@app.route('/get_webhook_token', methods=['POST'])
def get_webhook_token():
    try:
        json_data = get_sanitized_json() or request.get_json()
        webhook_url = json_data.get('webhook_url') if json_data else None
        if not webhook_url:
            return jsonify({"error": "Webhook URL required"}), 400

        # Validate webhook URL format
        try:
            parsed = urlparse(webhook_url)
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError("Invalid URL format")
        except:
            return jsonify({"error": "Invalid webhook URL format"}), 400

        # Generate token
        token = generate_webhook_token(webhook_url)
        
        return jsonify({
            "token": token,
            "expires_in": WEBHOOK_TOKEN_EXPIRY
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Add new route for search page
@app.route('/search/')
def search_page():
    query = request.args.get('q', '')
    return render_template('index.html', search_query=query)

@app.route('/generate_file_id', methods=['GET'])
def get_file_id():
    """Generate a secure file ID for new uploads"""
    file_id = generate_file_id()  # Using existing generate_file_id function
    return jsonify({"file_id": file_id})

def secure_compare(a, b):
    """Secure string comparison using hmac"""
    return hmac.compare_digest(str(a).encode(), str(b).encode())

@app.route('/preview/<download_id>', methods=['GET'])
@verify_download_token
@limiter.limit("30/minute")
def preview_file(download_id):
    try:
        signature = request.headers.get('X-Chunk-Signature')
        token = request.headers.get('X-Download-Token')
        
        if not signature or not token:
            return jsonify({"error": "Missing required headers"}), 401

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.file_url, f.is_enabled, f.mime_type, f.file_size,
                   CASE WHEN f.password IS NOT NULL THEN 1 ELSE 0 END as has_password,
                   f.filename
            FROM files f
            WHERE f.download_id = ? 
            AND f.part_number = 0
            AND f.is_chunk = 1
            LIMIT 1
        """, (download_id,))
        
        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({"error": "File not found"}), 404

        url, is_enabled, mime_type, file_size, has_password, filename = result

        # Security checks
        if not is_enabled:
            return jsonify({"error": "File is disabled"}), 403

        # Stream response
        headers = {
            'Content-Length': str(file_size)
        }

        try:
            response = requests.get(url, stream=True)
            return Response(
                response.iter_content(chunk_size=8192),
                status=200,
                headers=headers,
                direct_passthrough=True
            )
        except requests.RequestException as e:
            print(f"Media streaming error: {str(e)}")
            return jsonify({"error": "Failed to stream media from source"}), 502

    except Exception as e:
        print(f"Preview error: {str(e)}")
        return jsonify({"error": "Failed to load preview"}), 500

@app.route('/preview/image/<download_id>', methods=['GET'])
@verify_download_token
@limiter.limit("30/minute")
def preview_image(download_id):
    try:
        token = request.headers.get('X-Download-Token')
        if not token:
            return jsonify({"error": "Missing authentication"}), 401

        try:
            # Verify token and get payload
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if payload['download_id'] != download_id:
                raise jwt.InvalidTokenError
            
            if not payload.get('is_enabled'):
                return jsonify({"error": "File access is disabled"}), 403
            
            if payload.get('has_password') and not payload.get('is_verified'):
                return jsonify({"error": "Password verification required"}), 401
            
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # Get image data with all needed checks
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.file_url, f.mime_type, f.filename, f.is_enabled,
                   CASE WHEN f.password IS NOT NULL THEN 1 ELSE 0 END as has_password
            FROM files f
            WHERE f.download_id = ? 
            AND f.is_chunk = 1
            AND f.mime_type LIKE 'image/%'
            ORDER BY f.part_number ASC
            LIMIT 1
        """, (download_id,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({"error": "Image not found"}), 404

        file_url, mime_type, filename, is_enabled, has_password = result

        # Security checks
        if not is_enabled:
            return jsonify({"error": "File is disabled"}), 403
        if has_password and not session.get(f'verified_{download_id}'):
            return jsonify({"error": "Password required"}), 401

        # Refresh CDN link for image
        refreshed_url = refresh_cdn_links(file_url)
        if not refreshed_url:
            return jsonify({"error": "Failed to refresh CDN link"}), 500

        # Create preview token with security info
        preview_token = create_preview_token(
            download_id, 
            refreshed_url, 
            request.headers,
            is_enabled=is_enabled,
            has_password=has_password,
            is_verified=session.get(f'verified_{download_id}', False)
        )

        # Save image to temp file
        extension = '.img'  # Generic extension for images
        temp_path = save_media_to_temp(refreshed_url, preview_token, extension)
        
        # Store token data with file info
        TEMP_TOKENS[preview_token] = {
            'download_id': download_id,
            'file_url': refreshed_url,
            'extension': extension,
            'used': False,
            'created': time.time(),
            'expires': time.time() + TEMP_FILES_EXPIRE,
            'is_enabled': is_enabled,
            'has_password': has_password,
            'is_verified': session.get(f'verified_{download_id}', False),
            'mime_type': mime_type
        }

        # Generate streaming URL
        image_url = url_for('stream_preview_image', 
                          token=preview_token,
                          _external=True)

        return jsonify({
            "url": image_url,
            "token": preview_token,
            "expires_in": TEMP_FILES_EXPIRE,
            "mime_type": mime_type
        })

    except Exception as e:
        print(f"Image preview error: {str(e)}")
        return jsonify({"error": "Failed to create preview"}), 500

@app.route('/preview/stream/image/<token>')
def stream_preview_image(token):
    try:
        if token not in TEMP_TOKENS:
            return jsonify({"error": "Invalid or expired token"}), 404

        token_data = TEMP_TOKENS[token]
        
        # Refresh CDN link for the image file
        refreshed_url = refresh_cdn_links(token_data['file_url'])
        if not refreshed_url:
            return jsonify({"error": "Failed to refresh CDN link"}), 500

        token_data['file_url'] = refreshed_url

        return stream_media_file(token, 'image/*')
    except Exception as e:
        print(f"Stream image error: {str(e)}")
        cleanup_token(token)
        return jsonify({"error": "Failed to stream image"}), 500

# Remove all existing preview_pdf route declarations and keep only this one
@app.route('/preview/pdf/<download_id>', methods=['GET'])
@verify_download_token
@limiter.limit("30/minute")
def preview_pdf(download_id):
    try:
        token = request.headers.get('X-Download-Token')
        if not token:
            return jsonify({"error": "Missing authentication"}), 401

        try:
            # Verify token and get payload
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if payload['download_id'] != download_id:
                raise jwt.InvalidTokenError
            
            if not payload.get('is_enabled'):
                return jsonify({"error": "File access is disabled"}), 403
            
            if payload.get('has_password') and not payload.get('is_verified'):
                return jsonify({"error": "Password verification required"}), 401
            
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # Get PDF data
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get all chunks data
        cursor.execute("""
            SELECT f.file_url, f.mime_type, f.filename, f.file_size, f.part_number,
                   f.is_enabled, f.total_parts,
                   CASE WHEN f.password IS NOT NULL THEN 1 ELSE 0 END as has_password
            FROM files f
            WHERE f.download_id = ? 
            AND f.is_chunk = 1
            AND f.mime_type = 'application/pdf'
            ORDER BY f.part_number ASC
            LIMIT 3
        """, (download_id,))
        chunks = cursor.fetchall()
        conn.close()

        if not chunks:
            return jsonify({"error": "PDF not found"}), 404

        # Get basic info from first chunk
        first_chunk = chunks[0]
        filename = first_chunk[2]
        mime_type = first_chunk[1]
        is_enabled = first_chunk[5]
        has_password = first_chunk[7]
        total_size = sum(chunk[3] for chunk in chunks)

        # Security checks
        if not is_enabled:
            return jsonify({"error": "File is disabled"}), 403
        if has_password and not session.get(f'verified_{download_id}'):
            return jsonify({"error": "Password required"}), 401

        # Create unique token for this preview session
        preview_token = create_preview_token(
            download_id,
            None,  # We'll set the URL after merging
            request.headers,
            is_enabled=is_enabled,
            has_password=has_password,
            is_verified=session.get(f'verified_{download_id}', False)
        )

        # Refresh CDN links and download chunks
        merged_file = None
        temp_chunks = []
        
        try:
            # Download and merge chunks
            for chunk in chunks:
                chunk_url = chunk[0]
                # Refresh CDN link for each chunk
                refreshed_url = refresh_cdn_links(chunk_url)
                if not refreshed_url:
                    raise Exception(f"Failed to refresh CDN link for chunk {chunk[4]}")

                # Download chunk to temp file
                temp_chunk = TEMP_FILES_DIR / f"{preview_token}_chunk_{chunk[4]}.tmp"
                with requests.get(refreshed_url, stream=True) as r:
                    with open(temp_chunk, 'wb') as f:
                        for data in r.iter_content(chunk_size=8192):
                            if data:
                                f.write(data)
                temp_chunks.append(temp_chunk)

            # Merge chunks if multiple
            if len(temp_chunks) > 1:
                merged_file = TEMP_FILES_DIR / f"{preview_token}.pdf"
                with open(merged_file, 'wb') as outfile:
                    for temp_chunk in temp_chunks:
                        with open(temp_chunk, 'rb') as infile:
                            shutil.copyfileobj(infile, outfile)
            else:
                # Just rename single chunk to final file
                merged_file = TEMP_FILES_DIR / f"{preview_token}.pdf"
                shutil.move(temp_chunks[0], merged_file)

        except Exception as e:
            # Cleanup on error
            for chunk in temp_chunks:
                if chunk.exists():
                    chunk.unlink()
            if merged_file and merged_file.exists():
                merged_file.unlink()
            raise e

        finally:
            # Cleanup temp chunks
            for chunk in temp_chunks:
                if chunk.exists():
                    chunk.unlink()

        # Store token data
        TEMP_TOKENS[preview_token] = {
            'download_id': download_id,
            'file_path': str(merged_file),
            'extension': '.pdf',
            'used': False,
            'created': time.time(),
            'expires': time.time() + TEMP_FILES_EXPIRE,
            'is_enabled': is_enabled,
            'has_password': has_password,
            'is_verified': session.get(f'verified_{download_id}', False),
            'mime_type': mime_type,
            'filename': filename,
            'total_size': total_size
        }

        # Generate streaming URL
        preview_url = url_for('stream_preview_pdf', 
                          token=preview_token,
                          filename=filename,
                          _external=True)

        return jsonify({
            "url": preview_url,
            "token": preview_token,
            "expires_in": TEMP_FILES_EXPIRE,
            "filename": filename
        })

    except Exception as e:
        print(f"PDF preview error: {str(e)}")
        return jsonify({"error": "Failed to create preview"}), 500

@app.route('/preview/stream/pdf/<token>')
def stream_preview_pdf(token):
    try:
        if token not in TEMP_TOKENS:
            return jsonify({"error": "Invalid or expired token"}), 404

        token_data = TEMP_TOKENS[token]
        file_path = Path(token_data['file_path'])
        
        if not file_path.exists():
            cleanup_token(token)
            return jsonify({"error": "PDF file not found"}), 404

        # Stream merged PDF file
        headers = {
            'Content-Type': 'application/pdf',
            'Content-Disposition': f'inline; filename="{token_data["filename"]}"',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Accept-Ranges': 'bytes'
        }

        def generate():
            try:
                with open(file_path, 'rb') as f:
                    while True:
                        data = f.read(8192)
                        if not data:
                            break
                        yield data
            finally:
                cleanup_token(token)

        return Response(
            generate(),
            headers=headers,
            direct_passthrough=True
        )
        
    except Exception as e:
        print(f"Stream PDF error: {str(e)}")
        cleanup_token(token)
        return jsonify({"error": "Failed to stream PDF"}), 500

@app.route('/preview/video/<download_id>', methods=['GET'])
def preview_video(download_id):
    try:
        token = request.headers.get('X-Download-Token')
        if not token:
            return jsonify({"error": "Missing authentication"}), 401

        try:
            # Verify token and get payload
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if payload['download_id'] != download_id:
                raise jwt.InvalidTokenError
                
            # Check enabled status from token
            if not payload.get('is_enabled'):
                return jsonify({"error": "File access is disabled"}), 403
                
            # Check password verification from token
            if payload.get('has_password') and not payload.get('is_verified'):
                return jsonify({"error": "Password verification required"}), 401
                
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # Double check with database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT file_url, mime_type, file_size, is_enabled,
                   CASE WHEN password IS NOT NULL THEN 1 ELSE 0 END as has_password 
            FROM files 
            WHERE download_id = ? AND is_chunk = 1 AND part_number = 0
        """, (download_id,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({"error": "Video not found"}), 404

        file_url, mime_type, file_size, is_enabled, has_password = result
        
        # Additional database-level security checks
        if not is_enabled:
            return jsonify({"error": "File access is disabled"}), 403
            
        if has_password and not session.get(f'verified_{download_id}'):
            return jsonify({"error": "Password verification required"}), 401

        # Create one-time preview token with security info
        preview_token = create_preview_token(
            download_id, 
            file_url, 
            request.headers,
            is_enabled=is_enabled,
            has_password=has_password,
            is_verified=session.get(f'verified_{download_id}', False)
        )
        
        # Generate direct video URL with token
        video_url = url_for('stream_preview_video', 
                          token=preview_token,
                          _external=True)

        return jsonify({
            "url": video_url,
            "token": preview_token,
            "expires_in": 300
        })

    except Exception as e:
        print(f"Video preview error: {str(e)}")
        return jsonify({"error": "Failed to create preview"}), 500

@app.route('/preview/stream/<token>.mp4')
def stream_preview_video(token):
    response = None  # Define response outside try block
    try:
        if token not in PREVIEW_TOKENS:
            print(f"Token not found: {token}")
            return jsonify({"error": "Invalid or expired token"}), 404

        token_data = PREVIEW_TOKENS[token]
        
        # Refresh CDN link for the video file
        refreshed_url = refresh_cdn_links(token_data['file_url'])
        if not refreshed_url:
            return jsonify({"error": "Failed to refresh CDN link"}), 500

        token_data['file_url'] = refreshed_url

        # Security checks...
        # ...existing security checks...

        # Stream video from Discord
        headers = {
            'Content-Type': 'video/mp4',
            'Accept-Ranges': 'bytes',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Connection': 'close'  # Ensure connection is closed properly
        }

        range_header = request.headers.get('Range', '')
        discord_headers = {
            'Range': range_header if range_header else 'bytes=0-',
            'User-Agent': 'Mozilla/5.0 Discord-Media-Proxy/1.0'
        }

        response = requests.get(token_data['file_url'], 
                              headers=discord_headers, 
                              stream=True)

        if response.status_code == 206:
            headers.update({
                'Content-Range': response.headers['Content-Range'],
                'Content-Length': response.headers['Content-Length']
            })

        class SafeStreamWrapper:
            def __init__(self, response, token):
                self.response = response
                self.token = token
                self.closed = False

            def generate(self):
                try:
                    for chunk in self.response.iter_content(chunk_size=8192):
                        if chunk:
                            try:
                                yield chunk
                            except (GeneratorExit, ConnectionAbortedError) as e:
                                # Handle client disconnection gracefully
                                print(f"Client disconnected while streaming token: {self.token}")
                                self.cleanup()
                                return
                except Exception as e:
                    print(f"Streaming error: {str(e)}")
                    self.cleanup()
                    raise
                finally:
                    self.cleanup()

            def cleanup(self):
                if not self.closed:
                    self.closed = True
                    if self.token in PREVIEW_TOKENS:
                        del PREVIEW_TOKENS[self.token]
                    if not self.response.raw.closed:
                        self.response.close()

        wrapper = SafeStreamWrapper(response, token)
        return Response(
            wrapper.generate(),
            status=response.status_code,
            headers=headers,
            direct_passthrough=True
        )

    except Exception as e:
        print(f"Stream error: {str(e)}")
        # Clean up resources
        if response and not response.raw.closed:
            response.close()
        if token in PREVIEW_TOKENS:
            del PREVIEW_TOKENS[token]
        return jsonify({"error": "Streaming failed"}), 500

@app.route('/preview/audio/<download_id>', methods=['GET'])
@verify_download_token
@limiter.limit("30/minute")
def preview_audio(download_id):
    try:
        token = request.headers.get('X-Download-Token')
        if not token:
            return jsonify({"error": "Missing authentication"}), 401

        try:
            # Verify token and get payload
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if payload['download_id'] != download_id:
                raise jwt.InvalidTokenError
            
            # Check enabled status from token
            if not payload.get('is_enabled'):
                return jsonify({"error": "File access is disabled"}), 403
            
            # Check password verification from token
            if payload.get('has_password') and not payload.get('is_verified'):
                return jsonify({"error": "Password verification required"}), 401
            
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # Get audio data with all needed checks
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.file_url, f.mime_type, f.filename, f.is_enabled,
                   CASE WHEN f.password IS NOT NULL THEN 1 ELSE 0 END as has_password
            FROM files f
            WHERE f.download_id = ? 
            AND f.is_chunk = 1
            AND f.mime_type LIKE 'audio/%'
            ORDER BY f.part_number ASC
            LIMIT 1
        """, (download_id,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({"error": "Audio not found"}), 404

        file_url, mime_type, filename, is_enabled, has_password = result

        # Security checks
        if not is_enabled:
            return jsonify({"error": "File is disabled"}), 403
        if has_password and not session.get(f'verified_{download_id}'):
            return jsonify({"error": "Password required"}), 401

        # Refresh CDN link for the audio file
        refreshed_url = refresh_cdn_links(file_url)
        if not refreshed_url:
            return jsonify({"error": "Failed to refresh CDN link"}), 500

        # Create preview token with security info
        preview_token = create_preview_token(
            download_id, 
            refreshed_url, 
            request.headers,
            is_enabled=is_enabled,
            has_password=has_password,
            is_verified=session.get(f'verified_{download_id}', False)
        )

        # Save audio to temp file
        extension = '.audio'  # Generic extension for audio
        temp_path = save_media_to_temp(refreshed_url, preview_token, extension)
        
        # Store token data with file info
        TEMP_TOKENS[preview_token] = {
            'download_id': download_id,
            'file_url': refreshed_url,
            'extension': extension,
            'used': False,
            'created': time.time(),
            'expires': time.time() + TEMP_FILES_EXPIRE,
            'is_enabled': is_enabled,
            'has_password': has_password,
            'is_verified': session.get(f'verified_{download_id}', False)
        }

        # Generate streaming URL
        audio_url = url_for('stream_preview_audio', 
                          token=preview_token,
                          _external=True)

        return jsonify({
            "url": audio_url,
            "token": preview_token,
            "expires_in": TEMP_FILES_EXPIRE,
            "mime_type": mime_type
        })

    except Exception as e:
        print(f"Audio preview error: {str(e)}")
        return jsonify({"error": "Failed to create preview"}), 500

@app.route('/preview/stream/audio/<token>')
def stream_preview_audio(token):
    try:
        if token not in TEMP_TOKENS:
            return jsonify({"error": "Invalid or expired token"}), 404

        token_data = TEMP_TOKENS[token]
        
        # Refresh CDN link for the audio file
        refreshed_url = refresh_cdn_links(token_data['file_url'])
        if not refreshed_url:
            return jsonify({"error": "Failed to refresh CDN link"}), 500

        token_data['file_url'] = refreshed_url

        return stream_media_file(token, 'audio/*')
    except Exception as e:
        print(f"Stream audio error: {str(e)}")
        cleanup_token(token)
        return jsonify({"error": "Failed to stream audio"}), 500

# Add after other helper functions, before route definitions
def save_media_to_temp(url, token, extension):
    """Download media to temp file and return path"""
    temp_path = TEMP_FILES_DIR / f"{token}{extension}"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 Discord-Media-Proxy/1.0',
        'Accept': '*/*'
    }
    
    with requests.get(url, headers=headers, stream=True) as response:
        response.raise_for_status()
        with open(temp_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    
    return temp_path

class PreviewFileManager:
    def __init__(self, token, temp_path, cleanup_delay=30):  # 30 seconds delay
        self.token = token
        self.temp_path = temp_path
        self.cleanup_delay = cleanup_delay
        self.cleanup_timer = None
        self.is_cleaned = False
        self.lock = threading.Lock()
        
    def schedule_cleanup(self):
        def delayed_cleanup():
            time.sleep(self.cleanup_delay)
            self.cleanup()
            
        self.cleanup_timer = threading.Thread(target=delayed_cleanup, daemon=True)
        self.cleanup_timer.start()
        
    def cleanup(self):
        with self.lock:
            if not self.is_cleaned:
                self.is_cleaned = True
                try:
                    if os.path.exists(self.temp_path):
                        os.unlink(self.temp_path)
                except Exception as e:
                    print(f"Error removing temp file: {e}")
                finally:
                    if self.token in TEMP_TOKENS:
                        del TEMP_TOKENS[self.token]

class SafeFileStreamer:
    def __init__(self, file_path, token):
        self.file_path = file_path
        self.token = token
        self.file = None
        self.closed = False
        self.preview_manager = PreviewFileManager(token, file_path)
        
    def generate(self):
        try:
            self.file = open(self.file_path, 'rb')
            # Start cleanup timer as soon as streaming begins
            self.preview_manager.schedule_cleanup()
            
            while True:
                data = self.file.read(8192)
                if not data:
                    break
                try:
                    yield data
                except (GeneratorExit, ConnectionAbortedError):
                    print(f"Client disconnected during streaming")
                    self.cleanup()
                    return
        except Exception as e:
            print(f"Error streaming file: {e}")
            self.cleanup()
            raise
        finally:
            self.cleanup()
            
    def cleanup(self):
        if not self.closed:
            self.closed = True
            if self.file:
                try:
                    self.file.close()
                except Exception as e:
                    print(f"Error closing file: {e}")
            self.preview_manager.cleanup()

def stream_media_file(token, mime_type):
    """Stream media from temp file with proper headers"""
    if token not in TEMP_TOKENS:
        return jsonify({"error": "Invalid or expired token"}), 404

    token_data = TEMP_TOKENS[token]

    try:
        # Security checks
        if not token_data.get('is_enabled'):
            return jsonify({"error": "File access is disabled"}), 403
        
        if token_data.get('has_password') and not token_data.get('is_verified'):
            return jsonify({"error": "Password verification required"}), 401
        
        # Check expiration
        if time.time() > token_data['expires']:
            return jsonify({"error": "Token expired"}), 410

        # Get temp file path
        extension = token_data.get('extension', '')
        temp_path = TEMP_FILES_DIR / f"{token}{extension}"
        
        if not temp_path.exists():
            return jsonify({"error": "Media file not found"}), 404

        headers = {
            'Content-Type': mime_type,
            'Accept-Ranges': 'bytes',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Connection': 'close',
            'X-Content-Type-Options': 'nosniff'
        }

        streamer = SafeFileStreamer(temp_path, token)
        return Response(
            streamer.generate(),
            headers=headers,
            direct_passthrough=True
        )

    except Exception as e:
        print(f"Stream error: {e}")
        return jsonify({"error": "Streaming failed"}), 500

def cleanup_token(token):
    """Remove token and associated temp file"""
    if token in TEMP_TOKENS:
        data = TEMP_TOKENS[token]
        temp_path = TEMP_FILES_DIR / f"{token}{data.get('extension', '')}"
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception as e:
                print(f"Error removing temp file: {e}")
        del TEMP_TOKENS[token]

# Add new helper function
def get_file_chunks(cursor, download_id):
    """Get all chunks for a file"""
    cursor.execute("""
        SELECT part_number, file_url, file_size
        FROM files 
        WHERE download_id = ? 
        AND is_chunk = 1
        ORDER BY part_number ASC
        LIMIT 5
    """, (download_id,))
    return cursor.fetchall()

def handle_multi_chunk_preview(download_id, refreshed_chunks, mime_type, total_size):
    """Handle preview for files with multiple chunks"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        if not refreshed_chunks or len(refreshed_chunks) > 4:  # Only allow up to 4 chunks
            return None
            
        # Download all chunks to temp files
        chunk_paths = []
        for part_number, chunk_url, chunk_size in refreshed_chunks:
            temp_path = TEMP_FILES_DIR / f"{token_urlsafe(16)}.chunk"
            with requests.get(chunk_url, stream=True) as r:
                with open(temp_path, 'wb') as f:
                    for data in r.iter_content(8192):
                        if data:
                            f.write(data)
            chunk_paths.append(str(temp_path))
            
        # Initialize merger
        merger = SafeFileMerger(TEMP_FILES_DIR)
        
        # Merge chunks safely
        try:
            result = merger.merge_chunks(chunk_paths, total_size)
            return result
        finally:
            # Cleanup chunk files
            for path in chunk_paths:
                try:
                    os.unlink(path)
                except:
                    pass
                    
    except Exception as e:
        print(f"Error handling multi-chunk preview: {e}")
        return None
    finally:
        conn.close()

# Modify preview routes to handle multi-chunk files
@app.route('/preview/<type>/<download_id>', methods=['GET'])
@verify_download_token
@limiter.limit("30/minute")
def preview_media(type, download_id):
    try:
        # ...existing security checks...
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get file info including chunk count
        cursor.execute("""
            SELECT f.file_url, f.mime_type, f.file_size, f.total_parts,
                   f.is_enabled, 
                   CASE WHEN f.password IS NOT NULL THEN 1 ELSE 0 END as has_password
            FROM files f
            WHERE f.download_id = ? 
            AND f.is_chunk = 0
            LIMIT 1
        """, (download_id,))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({"error": "File not found"}), 404
            
        file_url, mime_type, file_size, total_parts, is_enabled, has_password = result
        
        # Handle multi-chunk files
        if total_parts > 1:
            if total_parts > 4:  # Only allow up to 4 chunks
                return jsonify({"error": "File too large for preview"}), 413
                
            chunks = get_file_chunks(cursor, download_id)
            if not chunks or len(chunks) > 4:
                return jsonify({"error": "Invalid chunk data"}), 500

            # Refresh CDN links for each chunk
            refreshed_chunks = []
            for chunk in chunks:
                part_number, chunk_url, chunk_size = chunk
                refreshed_url = refresh_cdn_links(chunk_url)
                if not refreshed_url:
                    return jsonify({"error": "Failed to refresh CDN link"}), 500
                refreshed_chunks.append((part_number, refreshed_url, chunk_size))

            # Handle merged preview
            merged = handle_multi_chunk_preview(
                download_id, refreshed_chunks, mime_type, file_size
            )
            
            if not merged:
                return jsonify({"error": "Failed to process file"}), 500
                
            # Create preview token with merged file info
            preview_token = create_preview_token(
                download_id,
                merged['path'],  # Use merged file path
                request.headers,
                is_enabled=is_enabled,
                has_password=has_password,
                is_verified=session.get(f'verified_{download_id}', False)
            )
            
            # Store additional merged file info
            TEMP_TOKENS[preview_token].update({
                'is_merged': True,
                'file_hash': merged['hash'],
                'merged_size': merged['size']
            })
            
        else:
            # Handle single chunk files as before
            refreshed_url = refresh_cdn_links(file_url)
            if not refreshed_url:
                return jsonify({"error": "Failed to refresh CDN link"}), 500

            preview_token = create_preview_token(
                download_id,
                refreshed_url,
                request.headers,
                is_enabled=is_enabled,
                has_password=has_password,
                is_verified=session.get(f'verified_{download_id}', False)
            )
        
        # Generate preview URL
        preview_url = url_for(f'stream_preview_{type}',
                            token=preview_token,
                            _external=True)
        
        return jsonify({
            "url": preview_url,
            "token": preview_token,
            "expires_in": TEMP_FILES_EXPIRE
        })
        
    except Exception as e:
        print(f"Preview error: {e}")
        return jsonify({"error": "Failed to create preview"}), 500

# Modify cleanup function to handle merged files
def cleanup_token(token):
    """Remove token and associated temp files"""
    if token in TEMP_TOKENS:
        data = TEMP_TOKENS[token]
        
        # Clean up temp file
        if data.get('is_merged'):
            # For merged files, file_url contains the temp file path
            if os.path.exists(data['file_url']):
                try:
                    os.unlink(data['file_url'])
                except Exception as e:
                    print(f"Error removing merged file: {e}")
        else:
            # Regular preview cleanup
            temp_path = TEMP_FILES_DIR / f"{token}{data.get('extension', '')}"
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception as e:
                    print(f"Error removing temp file: {e}")
                    
        del TEMP_TOKENS[token]

@app.teardown_request
def teardown_request(exception=None):
    session_id = getattr(g, 'session_id', None)
    if session_id:
        # Release all webhooks used by this session
        for webhook in webhook_manager.webhooks:
            webhook_manager.release_webhook(webhook, session_id)

def cleanup_all_temp_files():
    """Clean up all temporary files and directories on startup"""
    try:
        # Clean temp directory
        if os.path.exists(TEMP_DIR):
            shutil.rmtree(TEMP_DIR)
            os.makedirs(TEMP_DIR)
            print("Cleaned temp directory")
            
        # Clean preview directory
        if os.path.exists(TEMP_FILES_DIR):
            shutil.rmtree(TEMP_FILES_DIR)
            os.makedirs(TEMP_FILES_DIR)
            print("Cleaned preview directory")
            
        # Clear all tokens
        TEMP_TOKENS.clear()
        PREVIEW_TOKENS.clear()
        print("Cleared all tokens")
        
    except Exception as e:
        print(f"Error during startup cleanup: {e}")
        # Ensure directories exist even if cleanup fails
        os.makedirs(TEMP_DIR, exist_ok=True)
        os.makedirs(TEMP_FILES_DIR, exist_ok=True)

def init_app(app):
    """Initialize app configs and start background tasks"""
    with app.app_context():
        # Clean up all temp files on startup
        cleanup_all_temp_files()
        
        # Initialize cleanup thread
        start_cleanup_thread()
        
        # Register teardown handlers
        app.teardown_appcontext(lambda exc: teardown_request())
        
        # Register signal handlers for graceful shutdown
        def shutdown_cleanup(*args):
            # Clean up any remaining temp files
            cleanup_all_temp_files()
            
        # Register shutdown handlers if not running in debug mode
        if not app.debug:
            import signal
            signal.signal(signal.SIGTERM, shutdown_cleanup)
            signal.signal(signal.SIGINT, shutdown_cleanup)

        return app

if __name__ == '__main__':
    setup_db()
    init_app(app)  # Initialize app
    validate_host(app)
    
    app.run(
        host='0.0.0.0',  # Bisa diakses dari luar
        port=5000,      # Port standar untuk development
        threaded=True
    )
