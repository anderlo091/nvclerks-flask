from flask import Flask, request, redirect, render_template_string, abort, url_for, session, jsonify, Response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, Regexp, URL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from flask_talisman import Talisman
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

# Configure logging for Vercel
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log', mode='a')
    ]
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

# Key versioning
KEY_VERSION = "1"
PREVIOUS_AES_GCM_KEY = None
PREVIOUS_HMAC_KEY = None

# Verify keys at startup
try:
    if len(AES_GCM_KEY) != 32:
        raise ValueError("AES-GCM key must be 32 bytes")
    Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(secrets.token_bytes(12)), backend=default_backend())
    logger.debug("AES-GCM key validated")
except Exception as e:
    logger.error(f"Invalid AES-GCM key: {str(e)}")
    raise ValueError(f"AES-GCM key initialization failed: {str(e)}")

try:
    if len(HMAC_KEY) != 32:
        raise ValueError("HMAC key must be 32 bytes")
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(b"test")
    h.finalize()
    logger.debug("HMAC key validated")
except Exception as e:
    logger.error(f"Invalid HMAC key: {str(e)}")
    raise ValueError(f"HMAC key initialization failed: {str(e)}")

# Flask configuration
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['WTF_CSRF_SECRET_KEY'] = WTF_CSRF_SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
logger.debug("Flask configuration set")

# Talisman for security headers
Talisman(app, force_https=True, strict_transport_security=True, hsts_preload=True)

# CSRF protection
csrf = CSRFProtect(app)

# WTForms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username required"),
        Length(min=2, max=100, message="Username must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Username: letters, numbers, _, @, or . only")
    ])
    next_url = HiddenField('Next')
    submit = SubmitField('Login')

class GenerateURLForm(FlaskForm):
    prefix = StringField('Prefix', validators=[
        DataRequired(message="Prefix required"),
        Length(min=2, max=100, message="Prefix must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9-]+$', message="Prefix: letters, numbers, or hyphens only")
    ])
    randomstring1 = StringField('Randomstring1', validators=[
        DataRequired(message="Randomstring1 required"),
        Length(min=2, max=100, message="Randomstring1 must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Randomstring1: letters, numbers, _, @, or . only")
    ])
    destination_link = StringField('Destination Link', validators=[
        DataRequired(message="Destination link required"),
        URL(message="Invalid URL (must start with http:// or https://)")
    ])
    randomstring2 = StringField('Randomstring2', validators=[
        DataRequired(message="Randomstring2 required"),
        Length(min=2, max=100, message="Randomstring2 must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Randomstring2: letters, numbers, _, @, or . only")
    ])
    expiry = SelectField('Expiry', choices=[
        ('3600', '1 Hour'),
        ('86400', '1 Day'),
        ('604800', '1 Week'),
        ('2592000', '1 Month')
    ], default='86400')
    analytics_enabled = BooleanField('Enable Analytics')
    submit = SubmitField('Generate URL')

# Valkey initialization
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
    logger.debug("Valkey connected")
except Exception as e:
    logger.error(f"Valkey connection failed: {str(e)}", exc_info=True)
    valkey_client = None

# Custom Jinja2 filter
def datetime_filter(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError) as e:
        logger.error(f"Error formatting timestamp: {str(e)}")
        return "Not Available"

app.jinja_env.filters['datetime'] = datetime_filter

# Encryption and key rotation
encryption_rotation = ['aes_gcm', 'hmac_sha256']
encryption_index_key = "encryption_index"
key_rotation_interval = 86400

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
                logger.debug("Encryption keys rotated")
    except Exception as e:
        logger.error(f"Error rotating keys: {str(e)}")

def get_next_encryption_method():
    try:
        if valkey_client:
            index = int(valkey_client.get(encryption_index_key) or 0)
            valkey_client.set(encryption_index_key, (index + 1) % len(encryption_rotation))
            return encryption_rotation[index % len(encryption_rotation)]
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
        logger.error(f"Error generating random string: {str(e)}")
        return secrets.token_urlsafe(length)

def get_base_domain():
    try:
        host = request.host
        logger.debug(f"Processing host: {host}")
        # Handle Vercel subdomains (e.g., app-name.vercel.app or custom domains)
        parts = host.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])  # e.g., vercel.app
            if parts[-2] in ['vercel', 'aivencloud']:  # Handle known platforms
                base_domain = host  # Use full host for Vercel/Aiven
            logger.debug(f"Base domain: {base_domain}")
            return base_domain
        return host
    except Exception as e:
        logger.error(f"Error getting base domain: {str(e)}")
        return "your-app.vercel.app"  # Update to your Vercel domain

def mimic_chase_response():
    headers = {
        'Server': 'AkamaiGHost',
        'Content-Type': 'text/html; charset=UTF-8',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }
    logger.debug("Generated Chase-like headers")
    return headers

def check_behavior(ip):
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
                data['requests'] = data['requests'][-10:]
            intervals = [data['requests'][i+1]['time'] - data['requests'][i]['time'] for i in range(len(data['requests'])-1)]
            if intervals and (min(intervals) < 0.05 or 
                             len(set([r['user_agent'] for r in data['requests']])) > 2 or
                             not any(h in headers.get('Accept', '') for h in ['text/html', 'application/xhtml+xml']) or
                             not headers.get('Accept-Language')):
                logger.warning(f"Suspicious behavior for IP {ip}")
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
        logger.debug(f"Behavior check passed for IP {ip}")
        return True
    except Exception as e:
        logger.error(f"Error checking behavior for IP {ip}: {str(e)}")
        return True

def get_valid_usernames():
    try:
        if valkey_client:
            cached = valkey_client.get("usernames")
            if cached:
                logger.debug("Retrieved usernames from Valkey")
                return json.loads(cached)
        response = requests.get(USER_TXT_URL)
        response.raise_for_status()
        usernames = [bleach.clean(line.strip()) for line in response.text.splitlines() if line.strip()]
        if valkey_client:
            valkey_client.setex("usernames", 3600, json.dumps(usernames))
            logger.debug("Cached usernames in Valkey")
        logger.debug(f"Fetched {len(usernames)} usernames")
        return usernames
    except Exception as e:
        logger.error(f"Error fetching usernames: {str(e)}")
        return []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'username' not in session:
                logger.debug(f"Redirecting to login from {request.url}")
                return redirect(url_for('login', next=request.url))
            logger.debug(f"Authenticated user: {session['username']}")
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in login_required: {str(e)}")
            return redirect(url_for('login'))
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
@rate_limit(limit=5, per=60)
def login():
    try:
        logger.debug(f"Accessing /login, method: {request.method}, next: {request.args.get('next')}")
        form = LoginForm()
        if form.validate_on_submit():
            username = bleach.clean(form.username.data.strip())
            logger.debug(f"Login attempt: {username}")
            valid_usernames = get_valid_usernames()
            if username in valid_usernames:
                session['username'] = username
                session.permanent = True
                session.modified = True
                logger.info(f"User {username} logged in")
                next_url = form.next_url.data or url_for('dashboard')
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
        logger.error(f"Login error: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response("Internal Server Error", status=500, headers=headers)

@app.route("/", methods=["GET"])
@rate_limit(limit=5, per=60)
def index():
    try:
        logger.debug(f"Accessing root, session: {'username' in session}")
        if 'username' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Index error: {str(e)}")
        headers = mimic_chase_response()
        return Response("Internal Server Error", status=500, headers=headers)

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
@rate_limit(limit=5, per=60)
def dashboard():
    try:
        username = session['username']
        logger.debug(f"Accessing dashboard for {username}")
        rotate_keys()
        base_domain = get_base_domain()
        form = GenerateURLForm()
        error = None

        if form.validate_on_submit():
            logger.debug(f"Form data: {form.data}")
            prefix = bleach.clean(form.prefix.data.strip())
            randomstring1 = bleach.clean(form.randomstring1.data.strip())
            destination_link = bleach.clean(form.destination_link.data.strip())
            randomstring2 = bleach.clean(form.randomstring2.data.strip())
            analytics_enabled = form.analytics_enabled.data
            expiry = int(form.expiry.data)

            parsed_url = urllib.parse.urlparse(destination_link)
            if not parsed_url.scheme in ('http', 'https') or not parsed_url.netloc:
                error = "Invalid URL: Must be http:// or https://"
                logger.warning(f"Invalid destination: {destination_link}")

            if not error:
                url_id = generate_random_string(16)
                timestamp = int(time.time())
                expiry_timestamp = timestamp + expiry
                payload = json.dumps({
                    "student_link": destination_link,
                    "timestamp": timestamp * 1000,
                    "expiry": expiry_timestamp
                })
                logger.debug(f"Payload: {payload}")

                try:
                    encryption_method = get_next_encryption_method()
                    encrypted_payload = encrypt_aes_gcm(payload) if encryption_method == 'aes_gcm' else encrypt_hmac_sha256(payload)
                    logger.debug(f"Encrypted payload: {encrypted_payload[:20]}...")
                except ValueError as e:
                    error = f"Encryption failed: {str(e)}"
                    logger.error(f"Encryption error: {str(e)}")

                if not error:
                    encoded_payload = base64.urlsafe_b64encode(encrypted_payload.encode('utf-8')).decode('utf-8')
                    path_segment = f"{randomstring1}{randomstring2}"
                    # Generate URL with proper encoding
                    query_params = {
                        'id': url_id,
                        'ts': timestamp,
                        'url': encoded_payload
                    }
                    query_string = urllib.parse.urlencode(query_params)
                    generated_url = f"https://{base_domain}/u/{urllib.parse.quote(username)}/link/{urllib.parse.quote(path_segment)}?{query_string}"
                    url_id_hash = hashlib.sha256(f"{url_id}:{encrypted_payload}".encode()).hexdigest()
                    logger.info(f"Generated URL: {generated_url}")

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
                            logger.info(f"Stored URL for {username}: {generated_url}")
                        except Exception as e:
                            error = "Failed to store URL"
                            logger.error(f"Valkey error: {str(e)}")
                    else:
                        error = "Database unavailable"
                        logger.warning("Valkey unavailable")

                    if not error:
                        return redirect(url_for('dashboard'))

        urls = []
        valkey_error = None
        if valkey_client:
            try:
                url_keys = valkey_client.keys(f"user:{username}:url:*")
                for key in url_keys:
                    url_data = valkey_client.hgetall(key)
                    if not url_data:
                        continue
                    url_id = key.split(':')[-1]
                    urls.append({
                        "url": url_data.get('url', ''),
                        "destination": url_data.get('destination', ''),
                        "created": datetime_filter(int(url_data.get('created', 0))),
                        "expiry": datetime_filter(int(url_data.get('expiry', 0))),
                        "clicks": int(url_data.get('clicks', 0)),
                        "analytics_enabled": url_data.get('analytics_enabled', '0') == '1',
                        "url_id": url_id
                    })
                logger.debug(f"Fetched {len(urls)} URLs for {username}")
            except Exception as e:
                valkey_error = "Unable to fetch URLs"
                logger.error(f"Valkey error fetching URLs: {str(e)}")
        else:
            valkey_error = "Database unavailable"

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
                    .error { background: #fee2e2; color: #b91c1c; }
                    .toggle-switch { position: relative; display: inline-block; width: 60px; height: 34px; }
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
                        <form method="POST" class="space-y-5">
                            {{ form.csrf_token }}
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Prefix</label>
                                {{ form.prefix(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
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
                                    <p class="text-gray-600"><strong>Clicks:</strong> {{ url.clicks }}</p>
                                    <div class="flex items-center mt-2">
                                        <label class="text-sm font-medium text-gray-700 mr-2">Analytics:</label>
                                        <label class="toggle-switch">
                                            <input type="checkbox" id="analytics-toggle-{{ loop.index }}" {% if url.analytics_enabled %}checked{% endif %} onchange="toggleAnalyticsSwitch('{{ url.url_id }}', '{{ loop.index }}')">
                                            <span class="slider"></span>
                                        </label>
                                    </div>
                                    <div class="mt-2">
                                        <a href="/delete_url/{{ url.url_id }}" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700" onclick="return confirm('Are you sure?')">Delete URL</a>
                                    </div>
                                </div>
                            {% endfor %}
                        {% else %}
                            <p class="text-gray-600">No URLs generated.</p>
                        {% endif %}
                    </div>
                </div>
            </body>
            </html>
        """, username=username, form=form, urls=urls, error=error, valkey_error=valkey_error)
    except Exception as e:
        logger.error(f"Dashboard error for {username}: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response("Internal Server Error", status=500, headers=headers)

@app.route("/bot-trap", methods=["GET"])
def bot_trap():
    try:
        ip = request.remote_addr
        logger.warning(f"Bot trapped at /bot-trap from IP: {ip}")
        if valkey_client:
            valkey_client.setex(f"blocked:{ip}", 86400, "bot_trap")
        headers = mimic_chase_response()
        return Response("Welcome to Chase Online Banking", status=200, headers=headers)
    except Exception as e:
        logger.error(f"Bot trap error: {str(e)}")
        headers = mimic_chase_response()
        return Response("Internal Server Error", status=500, headers=headers)

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
                logger.warning(f"URL {url_id} not found for {username}")
                return jsonify({"status": "error", "message": "URL not found"}), 404
            current = valkey_client.hget(key, "analytics_enabled")
            new_value = "0" if current == "1" else "1"
            valkey_client.hset(key, "analytics_enabled", new_value)
            logger.debug(f"Toggled analytics for URL {url_id} to {new_value}")
            return jsonify({"status": "ok"}), 200
        return jsonify({"status": "error", "message": "Database unavailable"}), 500
    except Exception as e:
        logger.error(f"Toggle analytics error: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/delete_url/<url_id>", methods=["GET"])
@login_required
def delete_url(url_id):
    try:
        username = session['username']
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for {username}")
                abort(404, "URL not found")
            valkey_client.delete(key)
            valkey_client.delete(f"url_payload:{url_id}")
            logger.debug(f"Deleted URL {url_id}")
            return redirect(url_for('dashboard'))
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
                    <p class="text-gray-600">Database unavailable.</p>
                </div>
            </body>
            </html>
        """), 500
    except Exception as e:
        logger.error(f"Delete URL error: {str(e)}")
        headers = mimic_chase_response()
        return Response("Internal Server Error", status=500, headers=headers)

@app.route("/u/<username>/link/<path:path_segment>", methods=["GET"])
@rate_limit(limit=5, per=60)
def redirect_handler(username, path_segment):
    try:
        logger.debug(f"Redirect handler: username={username}, path={path_segment}, query={request.query_string.decode()}, IP={request.remote_addr}")
        base_domain = get_base_domain()

        # Check blocked IP
        if valkey_client and valkey_client.exists(f"blocked:{request.remote_addr}"):
            logger.warning(f"Blocked IP {request.remote_addr}")
            headers = mimic_chase_response()
            return Response("Access Denied", status=403, headers=headers)

        # Scanner detection
        headers = mimic_chase_response()
        if 'User-Agent' in request.headers and any(keyword in request.headers['User-Agent'].lower() for keyword in ['bot', 'crawler', 'scanner', 'spider']):
            logger.debug("Detected scanner")
            return Response("Welcome to Chase Online Banking", status=200, headers=headers)

        # Behavioral analysis
        if not check_behavior(request.remote_addr):
            logger.warning(f"Behavioral check failed for IP {request.remote_addr}")
            return Response("Access Denied", status=403, headers=headers)

        # Parse query parameters
        url_id = request.args.get('id')
        timestamp = request.args.get('ts')
        encoded_payload = request.args.get('url')
        logger.debug(f"Query params: id={url_id}, ts={timestamp}, url={encoded_payload}")

        if not (url_id and timestamp and encoded_payload):
            logger.error("Missing query parameters")
            return Response("Invalid link format", status=400, headers=headers)

        # Extract randomstrings (no splitting assumption)
        randomstrings = path_segment
        logger.debug(f"Path segment: {randomstrings}")

        # Random delay
        delay = random.uniform(0.1, 0.2)
        time.sleep(delay)
        logger.debug(f"Delay: {delay:.3f}s")

        # Decode payload
        try:
            encrypted_payload = base64.urlsafe_b64decode(encoded_payload).decode('utf-8')
            logger.debug(f"Decoded payload: {encrypted_payload[:20]}...")
        except Exception as e:
            logger.error(f"Decode error: {str(e)}")
            return Response("Invalid link encoding", status=400, headers=headers)

        # Generate url_id_hash (match dashboard calculation)
        url_id_hash = hashlib.sha256(f"{url_id}:{encrypted_payload}".encode()).hexdigest()
        logger.debug(f"URL ID hash: {url_id_hash}")

        payload = None
        if valkey_client:
            try:
                cached_payload = valkey_client.get(f"url_payload:{url_id_hash}")
                if cached_payload:
                    payload = cached_payload
                    logger.debug(f"Using cached payload")
            except Exception as e:
                logger.error(f"Valkey cache error: {str(e)}")

        if not payload:
            encryption_method = 'aes_gcm'
            key_version = KEY_VERSION
            if valkey_client:
                try:
                    url_data = valkey_client.hgetall(f"user:{username}:url:{url_id_hash}")
                    if not url_data:
                        logger.error(f"No URL data found for hash: {url_id_hash}")
                        return Response("Link not found", status=404, headers=headers)
                    encryption_method = url_data.get('encryption_method', 'aes_gcm')
                    key_version = url_data.get('key_version', KEY_VERSION)
                    logger.debug(f"Valkey data: method={encryption_method}, version={key_version}")
                except Exception as e:
                    logger.error(f"Valkey error: {str(e)}")

            methods = [encryption_method]
            key_pairs = [(AES_GCM_KEY, HMAC_KEY)]
            if key_version != KEY_VERSION and PREVIOUS_AES_GCM_KEY and PREVIOUS_HMAC_KEY:
                key_pairs.append((PREVIOUS_AES_GCM_KEY, PREVIOUS_HMAC_KEY))

            for method in methods:
                for aes_key, hmac_key in key_pairs:
                    try:
                        if method == 'aes_gcm':
                            payload = decrypt_aes_gcm(encrypted_payload, key=aes_key)
                        else:
                            payload = decrypt_hmac_sha256(encrypted_payload, key=hmac_key)
                        logger.debug(f"Decrypted with {method}")
                        if valkey_client:
                            try:
                                expiry = json.loads(payload).get('expiry', int(time.time()) + 86400)
                                ttl = max(1, int(expiry - time.time()))
                                valkey_client.setex(f"url_payload:{url_id_hash}", ttl, payload)
                                logger.debug(f"Cached payload, TTL: {ttl}s")
                            except Exception as e:
                                logger.error(f"Valkey cache error: {str(e)}")
                        break
                    except ValueError as e:
                        logger.debug(f"Decryption failed: {method}, {str(e)}")
                        try:
                            json.loads(encrypted_payload)
                            payload = encrypted_payload
                            logger.warning("Unencrypted payload detected")
                            break
                        except json.JSONDecodeError:
                            continue
                if payload:
                    break

        if not payload:
            logger.error("Decryption failed")
            return Response("Invalid or corrupted link", status=400, headers=headers)

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            logger.debug(f"Payload: url={redirect_url}, expiry={expiry}")
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                return Response("Invalid destination URL", status=400, headers=headers)
            if time.time() > expiry:
                logger.warning("URL expired")
                if valkey_client:
                    valkey_client.delete(f"url_payload:{url_id_hash}")
                return Response("Link expired", status=410, headers=headers)
        except Exception as e:
            logger.error(f"Payload parse error: {str(e)}")
            return Response("Invalid link data", status=400, headers=headers)

        # Fake redirect
        if random.random() < 0.3:
            logger.debug("Fake redirect to chase.com")
            return redirect("https://www.chase.com", code=302, Response=Response(headers=headers))

        final_url = redirect_url.rstrip('/')
        logger.info(f"Redirecting to {final_url}")
        if valkey_client:
            try:
                analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id_hash}", "analytics_enabled") == "1"
                if analytics_enabled:
                    valkey_client.hincrby(f"user:{username}:url:{url_id_hash}", "clicks", 1)
                    logger.debug(f"Incremented clicks for {url_id_hash}")
            except Exception as e:
                logger.error(f"Valkey click error: {str(e)}")
        return redirect(final_url, code=302, Response=Response(headers=headers))
    except Exception as e:
        logger.error(f"Redirect error: {str(e)}", exc_info=True)
        headers = mimic_chase_response()
        return Response("Internal Server Error", status=500, headers=headers)

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.error(f"404 for path: {path}, host: {request.host}, url: {request.url}")
    headers = mimic_chase_response()
    return Response("Page Not Found", status=404, headers=headers)

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
    except Exception as e:
        logger.error(f"Error starting app: {str(e)}", exc_info=True)
        raise
