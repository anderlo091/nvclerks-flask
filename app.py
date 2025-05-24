from flask import Flask, request, redirect, render_template_string, abort, url_for, session, Response
from flask_wtf import FlaskForm
from wtforms import SubmitField
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
from datetime import datetime, timedelta
import uuid
import hashlib
from valkey import Valkey
from functools import wraps
import requests
from user_agents import parse
from dotenv import load_dotenv
import csv
from io import StringIO

app = Flask(__name__)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.debug("Initializing Flask app")

# Configurations (embedded)
FLASK_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = secrets.token_bytes(32)
HMAC_KEY = secrets.token_bytes(32)
VALKEY_HOST = "valkey-137d99b9-reign.e.aivencloud.com"
VALKEY_PORT = 25708
VALKEY_USERNAME = "default"
VALKEY_PASSWORD = "AVNS_Yzfa75IOznjCrZJIyzI"
USER_TXT_URL = os.getenv("USER_TXT_URL", "https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt")
DATA_RETENTION_DAYS = 90

# Dynamic domain handling
def get_base_domain():
    try:
        host = request.host
        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception as e:
        logger.error(f"Error getting base domain: {str(e)}")
        return "nvclerks.com"

# Flask configuration
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['WTF_CSRF_ENABLED'] = True
logger.debug("Flask configuration set")

# Valkey initialization
valkey_client = None
max_retries = 2
for attempt in range(max_retries):
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
        logger.debug("Valkey connection established")
        break
    except Exception as e:
        logger.error(f"Valkey connection failed on attempt {attempt+1}: {str(e)}")
        if attempt < max_retries - 1:
            time.sleep(0.5)
            continue
        raise ValueError("Failed to connect to Valkey")

# Custom Jinja2 filter for datetime
def datetime_filter(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S JST')
    except (TypeError, ValueError):
        return "Unknown"

app.jinja_env.filters['datetime'] = datetime_filter

# Bot detection patterns
BOT_PATTERNS = ["googlebot", "bingbot", "yandex", "duckduckbot", "curl/", "wget/", "headless"]

def is_bot(user_agent, headers, ip, endpoint):
    try:
        if 'username' in session:
            logger.debug(f"IP {ip} is authenticated, skipping bot check")
            return False, "Authenticated user"
        if endpoint.startswith("/") and endpoint != "/login":
            logger.debug(f"IP {ip} allowed for generated link {endpoint}")
            return False, "Generated link access"
        if not user_agent:
            logger.warning(f"Blocked IP {ip}: No User-Agent")
            return True, "Missing User-Agent"
        user_agent_lower = user_agent.lower()
        for pattern in BOT_PATTERNS:
            if pattern in user_agent_lower:
                logger.warning(f"Blocked IP {ip}: Known bot pattern {pattern}")
                return True, f"Known bot: {pattern}"
        if 'HeadlessChrome' in user_agent or 'PhantomJS' in user_agent:
            logger.warning(f"Blocked IP {ip}: Headless browser")
            return True, "Headless browser"
        key = f"bot_check:{ip}"
        count = valkey_client.get(key)
        if count and int(count) > 10:
            logger.warning(f"Blocked IP {ip}: Rapid requests")
            return True, "Rapid requests"
        valkey_client.incr(key)
        valkey_client.expire(key, 60)
        if ip.startswith(('162.249.', '5.62.', '84.39.', '37.19.200.')):
            logger.warning(f"Blocked IP {ip}: Data center IP")
            return True, "Data center IP"
        if endpoint == "/login" and headers.get('Referer') and 'Mozilla' in user_agent:
            logger.debug(f"IP {ip} allowed for /login")
            return False, "Likely human (login)"
        logger.warning(f"Blocked IP {ip}: Missing JS verification")
        return True, "Missing JS verification"
    except Exception as e:
        logger.error(f"Error in is_bot for IP {ip}: {str(e)}")
        return True, "Error in bot detection"

def get_geoip(ip):
    try:
        cache_key = f"geoip:{ip}"
        cached = valkey_client.get(cache_key)
        if cached:
            logger.debug(f"GeoIP cache hit for IP {ip}")
            return json.loads(cached)
        max_retries = 2
        for attempt in range(max_retries):
            try:
                response = requests.get(f"https://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,query")
                response.raise_for_status()
                data = response.json()
                if data.get('status') != 'success':
                    logger.error(f"ip-api.com error for IP {ip}: {data.get('message', 'Unknown')}")
                    break
                result = {
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "region": data.get('regionName', 'Unknown'),
                    "lat": float(data.get('lat', 0.0)),
                    "lon": float(data.get('lon', 0.0)),
                    "isp": data.get('isp', 'Unknown'),
                    "timezone": data.get('timezone', 'Unknown')
                }
                valkey_client.setex(cache_key, 86400, json.dumps(result))
                logger.debug(f"GeoIP cached for IP {ip}")
                return result
            except Exception as e:
                logger.error(f"ip-api.com failed for IP {ip} on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
        return {"country": "Unknown", "city": "Unknown", "region": "Unknown", "lat": 0.0, "lon": 0.0, "isp": "Unknown", "timezone": "Unknown"}
    except Exception as e:
        logger.error(f"GeoIP failed for IP {ip}: {str(e)}")
        return {"country": "Unknown", "city": "Unknown", "region": "Unknown", "lat": 0.0, "lon": 0.0, "isp": "Unknown", "timezone": "Unknown"}

def rate_limit(limit=5, per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            try:
                ip = request.remote_addr
                user_agent = request.headers.get("User-Agent", "")
                headers = request.headers
                endpoint = request.path
                is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, endpoint)
                if is_bot_flag:
                    logger.warning(f"Blocked request from IP {ip}: {bot_reason}")
                    abort(403, f"Access denied: {bot_reason}")
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
                logger.error(f"Error in rate_limit for IP {ip}: {str(e)}")
                return f(*args, **kwargs)
        return wrapped_function
    return decorator

def generate_fingerprint():
    try:
        headers = request.headers
        canvas = headers.get('X-Canvas-Fingerprint', '')
        fonts = headers.get('X-Fonts', '')
        plugins = headers.get('X-Plugins', '')
        ip = request.remote_addr
        raw = f"{canvas}{fonts}{plugins}{ip}{time.time()}"
        return hashlib.sha256(raw.encode()).hexdigest()
    except Exception as e:
        logger.error(f"Error in generate_fingerprint: {str(e)}")
        return hashlib.sha256(str(time.time()).encode()).hexdigest()

def encrypt_heap_x3(payload, fingerprint):
    try:
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = json.dumps({"payload": payload, "fingerprint": fingerprint}).encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag
        slug = secrets.token_hex(50)
        return f"{base64.urlsafe_b64encode(encrypted).decode()}.{slug}"
    except Exception as e:
        logger.error(f"HEAP X3 encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_heap_x3(encrypted):
    try:
        encrypted, _ = encrypted.split('.')
        encrypted = base64.urlsafe_b64decode(encrypted)
        iv = encrypted[:12]
        tag = encrypted[-16:]
        ciphertext = encrypted[12:-16]
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(decrypted.decode())
    except Exception as e:
        logger.error(f"HEAP X3 decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_slugstorm(payload):
    try:
        expiry = (datetime.utcnow() + timedelta(hours=24)).timestamp() * 1000
        data = json.dumps({"payload": payload, "expires": expiry})
        uuid_chain = f"{uuid.uuid4()}{secrets.token_hex(20)}"
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data.encode())
        signature = h.finalize()
        return f"{base64.urlsafe_b64encode(data.encode()).decode()}.{uuid_chain}.{base64.urlsafe_b64encode(signature).decode()}"
    except Exception as e:
        logger.error(f"SlugStorm encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_slugstorm(encrypted):
    try:
        data_b64, _, sig_b64 = encrypted.split('.')
        data = base64.urlsafe_b64decode(data_b64).decode()
        signature = base64.urlsafe_b64decode(sig_b64)
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data.encode())
        h.verify(signature)
        data = json.loads(data)
        if data['expires'] < int(time.time() * 1000):
            logger.warning("SlugStorm payload expired")
            raise ValueError("Payload expired")
        return data
    except Exception as e:
        logger.error(f"SlugStorm decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_pow(payload):
    try:
        iv = secrets.token_bytes(8)
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = payload.encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return base64.urlsafe_b64encode(iv + ciphertext).decode()
    except Exception as e:
        logger.error(f"PoW encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_pow(encrypted):
    try:
        encrypted = base64.urlsafe_b64decode(encrypted)
        iv = encrypted[:8]
        ciphertext = encrypted[8:]
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
    except Exception as e:
        logger.error(f"PoW decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_signed_token(payload):
    try:
        data = payload.encode()
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data)
        signature = h.finalize()
        return f"{base64.urlsafe_b64encode(data).decode()}.{base64.urlsafe_b64encode(signature).decode()}"
    except Exception as e:
        logger.error(f"Signed Token encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_signed_token(encrypted):
    try:
        data_b64, sig_b64 = encrypted.split('.')
        data = base64.urlsafe_b64decode(data_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data)
        h.verify(signature)
        return data.decode()
    except Exception as e:
        logger.error(f"Signed Token decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def get_valid_usernames():
    try:
        cached = valkey_client.get("usernames")
        if cached:
            logger.debug("Retrieved usernames from Valkey cache")
            return json.loads(cached)
        response = requests.get(USER_TXT_URL)
        response.raise_for_status()
        usernames = [line.strip() for line in response.text.splitlines() if line.strip()]
        valkey_client.setex("usernames", 3600, json.dumps(usernames))
        logger.debug(f"Cached {len(usernames)} usernames in Valkey")
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

@app.before_request
def block_ohio_subdomain():
    try:
        if request.host == 'ohioautocollection.nvclerks.com':
            logger.debug(f"Redirecting {request.host} to https://google.com")
            return redirect("https://google.com", code=302)
    except Exception as e:
        logger.error(f"Error in block_ohio_subdomain: {str(e)}")

@app.before_request
def log_visitor():
    try:
        if request.path.startswith(('/static', '/challenge', '/fingerprint', '/denied', '/favicon.ico')):
            return
        username = session.get('username', 'default')
        user_agent = request.headers.get("User-Agent", "")
        ip = request.remote_addr
        headers = request.headers
        referer = headers.get("Referer", "")
        session_start = session.get('session_start', int(time.time()))
        session['session_start'] = session_start
        ua = parse(user_agent)
        device = "Desktop"
        if ua.is_mobile:
            device = "Android" if "Android" in user_agent else "iPhone" if "iPhone" in user_agent else "Mobile"
        app = f"{ua.browser.family} {ua.browser.version_string}"[:50] if ua.browser.family else "Unknown"
        is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, request.path)
        visit_type = "Human"
        if is_bot_flag:
            visit_type = "Bot" if "curl/" in user_agent.lower() else "Mimicry" if "Mimicry" in bot_reason else "Bot"
        elif app != "Unknown" and app != f"{ua.browser.family} {ua.browser.version_string}"[:50]:
            visit_type = "App"
        location = get_geoip(ip)
        session_duration = int(time.time()) - session_start
        visitor_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()
        encrypted_ip = encrypt_signed_token(ip)
        encrypted_ua = encrypt_signed_token(user_agent[:100])
        max_retries = 2
        for attempt in range(max_retries):
            try:
                valkey_client.hset(f"user:{username}:visitor:{visitor_id}", mapping={
                    "timestamp": int(time.time()),
                    "ip": encrypted_ip,
                    "country": location['country'],
                    "region": location['region'],
                    "city": location['city'],
                    "lat": str(location['lat']),
                    "lon": str(location['lon']),
                    "isp": location['isp'],
                    "timezone": location['timezone'],
                    "device": device,
                    "application": app,
                    "user_agent": encrypted_ua,
                    "bot_status": visit_type,
                    "block_reason": bot_reason if is_bot_flag else "N/A",
                    "referer": referer,
                    "source": 'referral' if referer else 'direct',
                    "session_duration": session_duration
                })
                valkey_client.expire(f"user:{username}:visitor:{visitor_id}", DATA_RETENTION_DAYS * 86400)
                logger.debug(f"Logged visitor: {visitor_id} for user: {username}")
                break
            except Exception as e:
                logger.error(f"Valkey error logging visitor on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
        if is_bot_flag:
            bot_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()
            for attempt in range(max_retries):
                try:
                    valkey_client.hset(f"user:{username}:bot:{bot_id}", mapping={
                        "timestamp": int(time.time()),
                        "ip": encrypted_ip,
                        "user_agent": encrypted_ua,
                        "block_reason": bot_reason
                    })
                    valkey_client.expire(f"user:{username}:bot:{bot_id}", DATA_RETENTION_DAYS * 86400)
                    logger.debug(f"Logged bot attempt: {bot_id} for user: {username}")
                    break
                except Exception as e:
                    logger.error(f"Valkey error logging bot attempt on attempt {attempt+1}: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(0.5)
                        continue
    except Exception as e:
        logger.error(f"Error in log_visitor: {str(e)}")

@app.route("/login", methods=["GET", "POST"])
@rate_limit(limit=5, per=60)
def login():
    try:
        logger.debug(f"Login accessed, method: {request.method}, next: {request.args.get('next', '')}")
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            logger.debug(f"Login attempt: {username}")
            valid_usernames = get_valid_usernames()
            if username in valid_usernames:
                session['username'] = username
                session.permanent = True
                session.modified = True
                logger.debug(f"User {username} logged in")
                next_url = request.form.get('next') or url_for('dashboard')
                return redirect(next_url)
            logger.warning(f"Invalid login attempt: {username}")
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
                    <script>
                        function sendChallenge() {
                            let challenge = 0;
                            for (let i = 0; i < 1000; i++) challenge += Math.random();
                            fetch('/challenge', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ challenge })
                            }).then(response => {
                                if (!response.ok) {
                                    console.error('Challenge failed:', response.status);
                                    setTimeout(sendChallenge, 1000);
                                }
                            }).catch(error => {
                                console.error('Challenge error:', error);
                                setTimeout(sendChallenge, 1000);
                            });
                        }
                        function getCanvasFingerprint() {
                            try {
                                const canvas = document.createElement('canvas');
                                const ctx = canvas.getContext('2d');
                                ctx.textBaseline = 'top';
                                ctx.font = '14px Arial';
                                ctx.fillText('Fingerprint', 2, 2);
                                return canvas.toDataURL();
                            } catch (e) {
                                console.error('Fingerprint error:', e);
                                return '';
                            }
                        }
                        window.onload = function() {
                            if (!window.fetch) {
                                console.error('JavaScript fetch not supported');
                                alert('Please enable JavaScript or use a modern browser.');
                                return;
                            }
                            sendChallenge();
                            fetch('/fingerprint', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ fingerprint: getCanvasFingerprint() })
                            }).catch(error => console.error('Fingerprint error:', error));
                        };
                    </script>
                </head>
                <body class="min-h-screen flex items-center justify-center p-4">
                    <div class="container bg-white p-8 rounded-xl shadow-2xl max-w-md w-full">
                        <h1 class="text-3xl font-extrabold mb-6 text-center text-gray-900">Login</h1>
                        <p class="text-red-600 mb-4 text-center">Invalid username. Please try again.</p>
                        <form method="POST" class="space-y-5">
                            <input type="hidden" name="next" value="{{ request.args.get('next', '') }}">
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Username</label>
                                <input type="text" name="username" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                            </div>
                            <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition">Login</button>
                        </form>
                    </div>
                </body>
                </html>
            """)
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
                <script>
                    function sendChallenge() {
                        let challenge = 0;
                        for (let i = 0; i < 1000; i++) challenge += Math.random();
                        fetch('/challenge', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ challenge })
                        }).then(response => {
                            if (!response.ok) {
                                console.error('Challenge failed:', response.status);
                                setTimeout(sendChallenge, 1000);
                            }
                        }).catch(error => {
                            console.error('Challenge error:', error);
                            setTimeout(sendChallenge, 1000);
                        });
                    }
                    function getCanvasFingerprint() {
                        try {
                            const canvas = document.createElement('canvas');
                            const ctx = canvas.getContext('2d');
                            ctx.textBaseline = 'top';
                            ctx.font = '14px Arial';
                            ctx.fillText('Fingerprint', 2, 2);
                            return canvas.toDataURL();
                        } catch (e) {
                            console.error('Fingerprint error:', e);
                            return '';
                        }
                    }
                    window.onload = function() {
                        if (!window.fetch) {
                            console.error('JavaScript fetch not supported');
                            alert('Please enable JavaScript or use a modern browser.');
                            return;
                        }
                        sendChallenge();
                        fetch('/fingerprint', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ fingerprint: getCanvasFingerprint() })
                        }).catch(error => console.error('Fingerprint error:', error));
                    };
                </script>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="container bg-white p-8 rounded-xl shadow-2xl max-w-md w-full">
                    <h1 class="text-3xl font-extrabold mb-6 text-center text-gray-900">Login</h1>
                    <form method="POST" class="space-y-5">
                        <input type="hidden" name="next" value="{{ request.args.get('next', '') }}">
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Username</label>
                            <input type="text" name="username" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                        </div>
                        <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition">Login</button>
                    </form>
                </div>
            </body>
            </html>
        """)
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/", methods=["GET"])
@rate_limit(limit=5, per=60)
def index():
    try:
        logger.debug(f"Root accessed, session: {'username' in session}")
        if 'username' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in index: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

class LinkForm(FlaskForm):
    subdomain = StringField('Subdomain', validators=[DataRequired()])
    randomstring1 = StringField('Randomstring1', validators=[DataRequired()])
    base64email = StringField('Base64email', validators=[DataRequired()])
    destination_link = StringField('Destination Link', validators=[DataRequired()])
    randomstring2 = StringField('Randomstring2', validators=[DataRequired()])
    expiry = SelectField('Expiry', choices=[
        ('3600', '1 Hour'),
        ('86400', '24 Hours'),
        ('604800', '1 Week'),
        ('2592000', '1 Month')
    ], validators=[DataRequired()])
    submit = SubmitField('Generate URL')

class DeleteForm(FlaskForm):
    submit = SubmitField('Delete')

class ClearViewsForm(FlaskForm):
    submit = SubmitField('Clear Views')

class ToggleForm(FlaskForm):
    submit = SubmitField('Toggle')

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
@rate_limit(limit=5, per=60)
def dashboard():
    try:
        username = session['username']
        logger.debug(f"Dashboard accessed for user: {username}")
        form = LinkForm()
        base_domain = get_base_domain()
        error = None
        success = None

        if request.method == "POST" and form.validate_on_submit():
            logger.debug(f"Processing form: {form.data}")
            subdomain = form.subdomain.data.strip().lower()
            randomstring1 = form.randomstring1.data.strip()
            base64email = form.base64email.data.strip()
            destination_link = form.destination_link.data.strip()
            randomstring2 = form.randomstring2.data.strip()
            expiry = int(form.expiry.data)

            if not re.match(r"^https?://", destination_link):
                error = "Invalid URL"
                logger.warning(f"Invalid destination_link: {destination_link}")
            elif not (2 <= len(subdomain) <= 100 and re.match(r"^[a-z0-9-]{2,100}$", subdomain)):
                error = "Subdomain must be 2-100 characters (letters, numbers, or hyphens)"
                logger.warning(f"Invalid subdomain: {subdomain}")
            elif not (2 <= len(randomstring1) <= 100 and re.match(r"^[A-Za-z0-9_@.]{2,100}$", randomstring1)):
                error = "Randomstring1 must be 2-100 characters (letters, numbers, _, @, .)"
                logger.warning(f"Invalid randomstring1: {randomstring1}")
            elif not (2 <= len(randomstring2) <= 100 and re.match(r"^[A-Za-z0-9_@.]{2,100}$", randomstring2)):
                error = "Randomstring2 must be 2-100 characters (letters, numbers, _, @, .)"
                logger.warning(f"Invalid randomstring2: {randomstring2}")
            elif not (2 <= len(base64email) <= 100 and re.match(r"^[A-Za-z0-9_@.]{2,100}$", base64email)):
                error = "Base64email must be 2-100 characters (letters, numbers, _, @, .)"
                logger.warning(f"Invalid base64email: {base64email}")

            if not error:
                path_segment = f"{randomstring1}{base64email}{randomstring2}"
                endpoint = generate_random_string(8)
                encryption_methods = ['heap_x3', 'slugstorm', 'pow', 'signed_token']
                method = secrets.choice(encryption_methods)
                fingerprint = generate_fingerprint()
                expiry_timestamp = int(time.time()) + expiry
                payload = json.dumps({
                    "student_link": destination_link,
                    "timestamp": int(time.time() * 1000),
                    "randomstring1": randomstring1,
                    "randomstring2": randomstring2,
                    "expiry": expiry_timestamp
                })

                try:
                    if method == 'heap_x3':
                        encrypted_payload = encrypt_heap_x3(payload, fingerprint)
                    elif method == 'slugstorm':
                        encrypted_payload = encrypt_slugstorm(payload)
                    elif method == 'pow':
                        encrypted_payload = encrypt_pow(payload)
                    else:
                        encrypted_payload = encrypt_signed_token(payload)
                except Exception as e:
                    logger.error(f"Encryption failed with {method}: {str(e)}")
                    error = "Failed to encrypt payload"

                if not error:
                    generated_url = f"https://{urllib.parse.quote(subdomain)}.{base_domain}/{endpoint}/{urllib.parse.quote(encrypted_payload, safe='')}/{urllib.parse.quote(path_segment, safe='/')}"
                    url_id = hashlib.sha256(generated_url.encode()).hexdigest()
                    max_retries = 2
                    for attempt in range(max_retries):
                        try:
                            valkey_client.hset(f"user:{username}:url:{url_id}", mapping={
                                "url": generated_url,
                                "destination": destination_link,
                                "path_segment": path_segment,
                                "created": int(time.time()),
                                "expiry": expiry_timestamp,
                                "clicks": 0,
                                "disabled": "0"
                            })
                            valkey_client.expire(f"user:{username}:url:{url_id}", DATA_RETENTION_DAYS * 86400)
                            logger.info(f"Generated URL for {username}: {generated_url}, url_id: {url_id}, key: user:{username}:url:{url_id}")
                            success = f"URL generated: <a href='{generated_url}' target='_blank'>{generated_url}</a>"
                            break
                        except Exception as e:
                            logger.error(f"Valkey error storing URL on attempt {attempt+1}: {str(e)}")
                            if attempt < max_retries - 1:
                                time.sleep(0.5)
                                continue
                            error = "Failed to store URL in database"
                            break

        urls = []
        valkey_error = None
        try:
            max_retries = 2
            url_keys = []
            for attempt in range(max_retries):
                try:
                    url_keys = valkey_client.keys(f"user:{username}:url:*")
                    logger.debug(f"Found {len(url_keys)} URL keys for user: {username}")
                    break
                except Exception as e:
                    logger.error(f"Valkey error fetching URL keys on attempt {attempt+1}: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(0.5)
                        continue
                    valkey_error = "Unable to fetch URL history"
                    break
            for key in url_keys:
                try:
                    url_data = valkey_client.hgetall(key)
                    if not url_data:
                        logger.warning(f"Empty data for key {key}")
                        continue
                    url_id = key.split(':')[-1]
                    visits = valkey_client.lrange(f"user:{username}:url:{url_id}:visits", 0, -1)
                    visit_data = []
                    for v in visits:
                        try:
                            visit_data.append(json.loads(v))
                        except json.JSONDecodeError:
                            logger.error(f"Error decoding visit data for {key}")
                    click_trends = {}
                    country_counts = {}
                    device_counts = {}
                    for visit in visit_data:
                        try:
                            date = datetime.fromtimestamp(visit.get('timestamp', 0)).strftime('%Y-%m-%d')
                            click_trends[date] = click_trends.get(date, 0) + 1
                            country = visit.get('location', {}).get('country', 'Unknown')
                            device = visit.get('device', 'Unknown')
                            country_counts[country] = country_counts.get(country, 0) + 1
                            device_counts[device] = device_counts.get(device, 0) + 1
                        except (KeyError, ValueError):
                            logger.error(f"Error processing visit data")
                    urls.append({
                        "url": url_data.get('url', ''),
                        "destination": url_data.get('destination', ''),
                        "path_segment": url_data.get('path_segment', ''),
                        "created": datetime.fromtimestamp(int(url_data.get('created', 0))).strftime('%Y-%m-%d %H:%M:%S JST') if url_data.get('created') else 'Unknown',
                        "expiry": int(url_data.get('expiry', 0)),
                        "clicks": int(url_data.get('clicks', 0)) if url_data.get('clicks') else 0,
                        "visits": visit_data,
                        "click_trends_keys": list(click_trends.keys()),
                        "click_trends_values": list(click_trends.values()),
                        "country_counts_keys": list(country_counts.keys()),
                        "country_counts_values": list(country_counts.values()),
                        "device_counts_keys": list(device_counts.keys()),
                        "device_counts_values": list(device_counts.values()),
                        "disabled": url_data.get('disabled', '0') == '1',
                        "id": url_id
                    })
                except Exception as e:
                    logger.error(f"Error processing URL key {key}: {str(e)}")
        except Exception as e:
            logger.error(f"Valkey error fetching URLs: {str(e)}")
            valkey_error = "Unable to fetch URL history"

        visitors = []
        bot_logs = []
        access_logs = []
        traffic_sources = {"direct": 0, "referral": 0}
        bot_ratio = {"human": 0, "bot": 0}
        try:
            max_retries = 2
            visitor_keys = []
            for attempt in range(max_retries):
                try:
                    visitor_keys = valkey_client.keys(f"user:{username}:visitor:*")
                    logger.debug(f"Found {len(visitor_keys)} visitor keys for user: {username}")
                    break
                except Exception as e:
                    logger.error(f"Valkey error fetching visitor keys on attempt {attempt+1}: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(0.5)
                        continue
                    valkey_error = "Unable to fetch visitor data"
                    break
            for key in visitor_keys:
                try:
                    visitor_data = valkey_client.hgetall(key)
                    if not visitor_data:
                        logger.warning(f"Empty visitor data for key {key}")
                        continue
                    source = 'referral' if visitor_data.get('referer') else 'direct'
                    decrypted_ip = decrypt_signed_token(visitor_data.get('ip', encrypt_signed_token('Unknown')))
                    decrypted_ua = decrypt_signed_token(visitor_data.get('user_agent', encrypt_signed_token('Unknown')))
                    visitors.append({
                        "timestamp": int(visitor_data.get('timestamp', 0)),
                        "ip": decrypted_ip,
                        "country": visitor_data.get('country', 'Unknown'),
                        "region": visitor_data.get('region', 'Unknown'),
                        "city": visitor_data.get('city', 'Unknown'),
                        "lat": float(visitor_data.get('lat', 0.0)),
                        "lon": float(visitor_data.get('lon', 0.0)),
                        "isp": visitor_data.get('isp', 'Unknown'),
                        "timezone": visitor_data.get('timezone', 'Unknown'),
                        "device": visitor_data.get('device', 'Unknown'),
                        "application": visitor_data.get('application', 'Unknown'),
                        "user_agent": decrypted_ua,
                        "bot_status": visitor_data.get('bot_status', 'Unknown'),
                        "block_reason": visitor_data.get('block_reason', 'N/A'),
                        "source": source,
                        "session_duration": int(visitor_data.get('session_duration', 0))
                    })
                    if visitor_data.get('bot_status') != 'Human':
                        bot_logs.append({
                            "timestamp": visitor_data.get('timestamp', 'Unknown'),
                            "ip": decrypted_ip,
                            "block_reason": visitor_data.get('block_reason', 'Unknown')
                        })
                        bot_ratio['bot'] += 1
                    else:
                        bot_ratio['human'] += 1
                    traffic_sources[source] = traffic_sources.get(source, 0) + 1
                except Exception as e:
                    logger.error(f"Error processing visitor key {key}: {str(e)}")
            for url in urls:
                access_keys = valkey_client.keys(f"user:{username}:url:{url['id']}:access:*")
                for key in access_keys:
                    try:
                        access_data = valkey_client.hgetall(key)
                        if not access_data:
                            continue
                        access_logs.append({
                            "url_id": url['id'],
                            "timestamp": datetime.fromtimestamp(int(access_data.get('timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S JST') if access_data.get('timestamp') else 'Unknown',
                            "ip": decrypt_signed_token(access_data.get('ip', encrypt_signed_token('Unknown'))),
                            "success": access_data.get('success', '0') == '1',
                            "reason": access_data.get('reason', 'N/A')
                        })
                    except Exception as e:
                        logger.error(f"Error processing access key {key}: {str(e)}")
        except Exception as e:
            logger.error(f"Valkey error fetching visitors: {str(e)}")
            valkey_error = "Unable to fetch visitor data"

        try:
            traffic_sources_keys = list(traffic_sources.keys())
            traffic_sources_values = list(traffic_sources.values())
            bot_ratio_keys = list(bot_ratio.keys())
            bot_ratio_values = list(bot_ratio.values())
            logger.debug(f"Traffic sources: {traffic_sources}, Bot ratio: {bot_ratio}")
        except Exception as e:
            logger.error(f"Error preparing chart data: {str(e)}")
            traffic_sources_keys = ["direct", "referral"]
            traffic_sources_values = [0, 0]
            bot_ratio_keys = ["human", "bot"]
            bot_ratio_values = [0, 0]

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
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
                <style>
                    body { background: linear-gradient(to right, #4f46e5, #7c3aed); color: #1f2937; }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                    .card { transition: all 0.3s; box-shadow: 0 10px 15px rgba(0,0,0,0.1); }
                    .card:hover { transform: translateY(-5px); }
                    canvas { max-height: 200px; }
                    .tab { cursor: pointer; transition: all 0.3s; }
                    .tab.active { background-color: #4f46e5; color: white; }
                    .table-container { max-height: 400px; overflow-y: auto; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { padding: 12px; text-align: left; }
                    th { background: #e5e7eb; position: sticky; top: 0; }
                    tr:nth-child(even) { background: #f9fafb; }
                    .error { background: #fee2e2; color: #b91c1c; }
                    .success { background: #d1fae5; color: #065f46; }
                    .bot { background: #fee2e2; }
                    .refresh-btn { animation: pulse 2s infinite; }
                    @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }
                    .expired { color: #b91c1c; }
                    .countdown { color: #1f2937; }
                </style>
                <script>
                    function toggleAnalytics(id) {
                        try {
                            const analytics = document.getElementById('analytics-' + id);
                            if (analytics) {
                                analytics.classList.toggle('hidden');
                            } else {
                                console.error('Analytics element not found: analytics-' + id);
                            }
                        } catch (e) {
                            console.error('Toggle analytics error:', e);
                        }
                    }
                    function applyFilters(id) {
                        try {
                            const device = document.getElementById('filter-device-' + id)?.value || '';
                            const type = document.getElementById('filter-type-' + id)?.value || '';
                            const rows = document.querySelectorAll('#visits-' + id + ' tr');
                            rows.forEach(row => {
                                const deviceCell = row.cells[2]?.textContent || '';
                                const typeCell = row.cells[4]?.textContent || '';
                                row.style.display = (
                                    (device === '' || deviceCell.includes(device)) &&
                                    (type === '' || typeCell.includes(type))
                                ) ? '' : 'none';
                            });
                        } catch (e) {
                            console.error('Filter error:', e);
                        }
                    }
                    function showTab(tabId) {
                        try {
                            const tabs = document.querySelectorAll('.tab-content');
                            const tabButtons = document.querySelectorAll('.tab');
                            const targetTab = document.getElementById(tabId);
                            if (!targetTab) {
                                console.error('Tab not found: ' + tabId);
                                return;
                            }
                            tabs.forEach(tab => tab.classList.add('hidden'));
                            tabButtons.forEach(tab => tab.classList.remove('active'));
                            targetTab.classList.remove('hidden');
                            const activeButton = document.querySelector(`[onclick="showTab('${tabId}')"]`);
                            if (activeButton) {
                                activeButton.classList.add('active');
                            } else {
                                console.error('Tab button not found for: ' + tabId);
                            }
                        } catch (e) {
                            console.error('Show tab error:', e);
                        }
                    }
                    function refreshDashboard() {
                        try {
                            window.location.reload();
                        } catch (e) {
                            console.error('Refresh error:', e);
                        }
                    }
                    function updateCountdowns() {
                        try {
                            document.querySelectorAll('.countdown').forEach(span => {
                                let expiry = parseInt(span.dataset.expiry);
                                let now = Math.floor(Date.now() / 1000);
                                if (now >= expiry) {
                                    span.textContent = 'Expired';
                                    span.classList.add('expired');
                                    return;
                                }
                                let seconds = expiry - now;
                                let hours = Math.floor(seconds / 3600);
                                let minutes = Math.floor((seconds % 3600) / 60);
                                let remaining = `${hours}h ${minutes}m`;
                                span.textContent = remaining;
                            });
                            setTimeout(updateCountdowns, 60000);
                        } catch (e) {
                            console.error('Countdown error:', e);
                        }
                    }
                    function applyVisitorFilters() {
                        try {
                            const country = document.getElementById('visitor-filter-country')?.value || '';
                            const device = document.getElementById('visitor-filter-device')?.value || '';
                            const timeRange = document.getElementById('visitor-filter-time')?.value || '';
                            const rows = document.querySelectorAll('#visitor-table tr');
                            const now = Math.floor(Date.now() / 1000);
                            rows.forEach(row => {
                                const countryCell = row.cells[2]?.textContent || '';
                                const deviceCell = row.cells[9]?.textContent || '';
                                const timestamp = parseInt(row.cells[0]?.dataset.timestamp || 0);
                                let show = true;
                                if (country && countryCell !== country) show = false;
                                if (device && deviceCell !== device) show = false;
                                if (timeRange) {
                                    const hours = parseInt(timeRange);
                                    if (timestamp < now - hours * 3600) show = false;
                                }
                                row.style.display = show ? '' : 'none';
                            });
                        } catch (e) {
                            console.error('Visitor filter error:', e);
                        }
                    }
                    function exportChartAsPNG(chartId, filename) {
                        try {
                            html2canvas(document.getElementById(chartId)).then(canvas => {
                                let link = document.createElement('a');
                                link.download = filename;
                                link.href = canvas.toDataURL('image/png');
                                link.click();
                            });
                        } catch (e) {
                            console.error('Export PNG error:', e);
                        }
                    }
                    function exportChartAsCSV(data, labels, filename) {
                        try {
                            let csv = 'Date,Value\n';
                            for (let i = 0; i < labels.length; i++) {
                                csv += `${labels[i]},${data[i]}\n`;
                            }
                            let blob = new Blob([csv], { type: 'text/csv' });
                            let link = document.createElement('a');
                            link.download = filename;
                            link.href = window.URL.createObjectURL(blob);
                            link.click();
                        } catch (e) {
                            console.error('Export CSV error:', e);
                        }
                    }
                    window.onload = function() {
                        try {
                            updateCountdowns();
                            showTab('urls-tab');
                        } catch (e) {
                            console.error('Onload error:', e);
                        }
                    };
                </script>
            </head>
            <body class="min-h-screen p-4">
                <div class="container max-w-7xl mx-auto">
                    <h1 class="text-4xl font-extrabold mb-8 text-center text-white">Welcome, {{ username }}</h1>
                    {% if error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ error }}</p>
                    {% endif %}
                    {% if success %}
                        <p class="success p-4 mb-4 text-center rounded-lg">{{ success | safe }}</p>
                    {% endif %}
                    {% if valkey_error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ valkey_error }}</p>
                    {% endif %}
                    <div class="flex space-x-4 mb-4">
                        <button class="tab px-4 py-2 bg-white rounded-lg active" onclick="showTab('urls-tab')">URLs</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('visitors-tab')">Visitor Views</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('bot-logs-tab')">Bot Logs</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('access-logs-tab')">Link Access Logs</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('analytics-tab')">Analytics</button>
                    </div>
                    <div id="urls-tab" class="tab-content">
                        <div class="bg-white p-8 rounded-xl card mb-8">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">Generate New URL</h2>
                            <form method="POST" class="space-y-5">
                                {{ form.hidden_tag() }}
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">{{ form.subdomain.label }}</label>
                                    {{ form.subdomain(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition", **{'title': "Subdomain must be 2-100 characters (letters, numbers, or hyphens)"}) }}
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">{{ form.randomstring1.label }}</label>
                                    {{ form.randomstring1(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition", **{'title': "Randomstring1 must be 2-100 characters (letters, numbers, _, @, .)"}) }}
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">{{ form.base64email.label }}</label>
                                    {{ form.base64email(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition", **{'title': "Base64email must be 2-100 characters (letters, numbers, _, @, .)"}) }}
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">{{ form.destination_link.label }}</label>
                                    {{ form.destination_link(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">{{ form.randomstring2.label }}</label>
                                    {{ form.randomstring2(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition", **{'title': "Randomstring2 must be 2-100 characters (letters, numbers, _, @, .)"}) }}
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">{{ form.expiry.label }}</label>
                                    {{ form.expiry(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
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
                                        <p class="text-gray-600"><strong>Path Segment:</strong> {{ url.path_segment }}</p>
                                        <p class="text-gray-600"><strong>Created:</strong> {{ url.created }}</p>
                                        <p class="text-gray-600"><strong>Expires:</strong> <span class="countdown" data-expiry="{{ url.expiry }}">{{ 'Expired' if url.expiry < now else url.expiry | datetime }}</span></p>
                                        <p class="text-gray-600"><strong>Clicks:</strong> {{ url.clicks }}</p>
                                        <p class="text-gray-600"><strong>Status:</strong> {{ 'Disabled' if url.disabled else 'Active' }}</p>
                                        <p class="text-gray-600"><strong>Preview:</strong> <a href="{{ url.destination }}" target="_blank" class="text-indigo-600">{{ url.destination }}</a></p>
                                        <div class="mt-2 flex space-x-2">
                                            <form action="{{ url_for('delete_url', url_id=url.id) }}" method="POST">
                                                {{ form.hidden_tag() }}
                                                <button type="submit" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700">Delete</button>
                                            </form>
                                            <form action="{{ url_for('clear_views', url_id=url.id) }}" method="POST">
                                                {{ form.hidden_tag() }}
                                                <button type="submit" class="bg-yellow-600 text-white px-4 py-2 rounded-lg hover:bg-yellow-700">Clear Views</button>
                                            </form>
                                            <form action="{{ url_for('toggle_url', url_id=url.id) }}" method="POST">
                                                {{ form.hidden_tag() }}
                                                <button type="submit" class="bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700">{{ 'Enable' if url.disabled else 'Disable' }}</button>
                                            </form>
                                            <button onclick="toggleAnalytics('{{ loop.index }}')" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700">Toggle Analytics</button>
                                        </div>
                                        <div id="analytics-{{ loop.index }}" class="hidden mt-4">
                                            <h4 class="text-lg font-semibold text-gray-900">Visitor Analytics</h4>
                                            <canvas id="chart-{{ loop.index }}" class="mt-4"></canvas>
                                            <script>
                                                try {
                                                    new Chart(document.getElementById('chart-{{ loop.index }}'), {
                                                        type: 'line',
                                                        data: {
                                                            labels: {{ url.click_trends_keys|tojson }},
                                                            datasets: [{
                                                                label: 'Clicks',
                                                                data: {{ url.click_trends_values|tojson }},
                                                                borderColor: '{{ primary_color }}',
                                                                fill: false
                                                            }]
                                                        },
                                                        options: {
                                                            scales: {
                                                                x: { title: { display: true, text: 'Date' } },
                                                                y: { title: { display: true, text: 'Clicks' }, beginAtZero: true }
                                                            }
                                                        }
                                                    });
                                                } catch (e) {
                                                    console.error('Chart error:', e);
                                                }
                                            </script>
                                            <div class="mt-4">
                                                <label class="block text-sm font-medium text-gray-700">Filter by Device</label>
                                                <select id="filter-device-{{ loop.index }}" onchange="applyFilters('{{ loop.index }}')" class="mt-1 w-full p-3 border rounded-lg">
                                                    <option value="">All</option>
                                                    <option value="Android">Android</option>
                                                    <option value="iPhone">iPhone</option>
                                                    <option value="Desktop">Desktop</option>
                                                </select>
                                            </div>
                                            <div class="mt-4">
                                                <label class="block text-sm font-medium text-gray-700">Filter by Type</label>
                                                <select id="filter-type-{{ loop.index }}" onchange="applyFilters('{{ loop.index }}')" class="mt-1 w-full p-3 border rounded-lg">
                                                    <option value="">All</option>
                                                    <option value="Human">Human</option>
                                                    <option value="Bot">Bot</option>
                                                    <option value="Mimicry">Mimicry</option>
                                                    <option value="App">App</option>
                                                </select>
                                            </div>
                                            <a href="/export/{{ loop.index }}" class="mt-4 inline-block bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700">Export as CSV</a>
                                            <div class="table-container mt-4">
                                                <table id="visits-{{ loop.index }}">
                                                    <thead>
                                                        <tr class="bg-gray-200">
                                                            <th>Timestamp</th>
                                                            <th>IP</th>
                                                            <th>Device</th>
                                                            <th>App</th>
                                                            <th>Type</th>
                                                            <th>Country</th>
                                                            <th>City</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {% if url.visits %}
                                                            {% for visit in url.visits %}
                                                                <tr class="{% if visit.type != 'Human' %}bot{% endif %}">
                                                                    <td>{{ visit.timestamp|datetime }}</td>
                                                                    <td>{{ decrypt_signed_token(visit.ip) }}</td>
                                                                    <td>{{ visit.device }}</td>
                                                                    <td>{{ visit.app }}</td>
                                                                    <td>{{ visit.type }}</td>
                                                                    <td>{{ visit.location.country }}</td>
                                                                    <td>{{ visit.location.city }}</td>
                                                                </tr>
                                                            {% endfor %}
                                                        {% else %}
                                                            <tr><td colspan="7" class="text-gray-600 text-center">No visitor data available</td></tr>
                                                        {% endif %}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                {% endfor %}
                            {% else %}
                                <p class="text-gray-600">No URLs generated yet.</p>
                            {% endif %}
                        </div>
                    </div>
                    <div id="visitors-tab" class="tab-content hidden">
                        <div class="bg-white p-8 rounded-xl card">
                            <div class="flex justify-between items-center mb-4">
                                <h2 class="text-2xl font-bold text-gray-900">Visitor Views</h2>
                                <button onclick="refreshDashboard()" class="refresh-btn bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">Refresh</button>
                            </div>
                            {% if visitors %}
                                <div class="mb-4 flex space-x-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700">Filter by Country</label>
                                        <select id="visitor-filter-country" onchange="applyVisitorFilters()" class="mt-1 w-full p-3 border rounded-lg">
                                            <option value="">All</option>
                                            {% for country in visitors|map(attribute='country')|unique %}
                                                <option value="{{ country }}">{{ country }}</option>
                                            {% endfor %}
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700">Filter by Device</label>
                                        <select id="visitor-filter-device" onchange="applyVisitorFilters()" class="mt-1 w-full p-3 border rounded-lg">
                                            <option value="">All</option>
                                            {% for device in visitors|map(attribute='device')|unique %}
                                                <option value="{{ device }}">{{ device }}</option>
                                            {% endfor %}
                                        </select>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700">Time Range</label>
                                        <select id="visitor-filter-time" onchange="applyVisitorFilters()" class="mt-1 w-full p-3 border rounded-lg">
                                            <option value="">All Time</option>
                                            <option value="24">Last 24 Hours</option>
                                            <option value="168">Last Week</option>
                                            <option value="720">Last Month</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="table-container">
                                    <table id="visitor-table">
                                        <thead>
                                            <tr class="bg-gray-200">
                                                <th>Timestamp</th>
                                                <th>IP</th>
                                                <th>Country</th>
                                                <th>Region</th>
                                                <th>City</th>
                                                <th>Lat</th>
                                                <th>Lon</th>
                                                <th>ISP</th>
                                                <th>Timezone</th>
                                                <th>Device</th>
                                                <th>Application</th>
                                                <th>User Agent</th>
                                                <th>Bot Status</th>
                                                <th>Block Reason</th>
                                                <th>Source</th>
                                                <th>Session Duration (s)</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for visitor in visitors %}
                                                <tr class="{% if visitor.bot_status != 'Human' %}bot{% endif %}">
                                                    <td data-timestamp="{{ visitor.timestamp }}">{{ visitor.timestamp | datetime }}</td>
                                                    <td>{{ visitor.ip }}</td>
                                                    <td>{{ visitor.country }}</td>
                                                    <td>{{ visitor.region }}</td>
                                                    <td>{{ visitor.city }}</td>
                                                    <td>{{ visitor.lat }}</td>
                                                    <td>{{ visitor.lon }}</td>
                                                    <td>{{ visitor.isp }}</td>
                                                    <td>{{ visitor.timezone }}</td>
                                                    <td>{{ visitor.device }}</td>
                                                    <td>{{ visitor.application }}</td>
                                                    <td>{{ visitor.user_agent }}</td>
                                                    <td>{{ visitor.bot_status }}</td>
                                                    <td>{{ visitor.block_reason }}</td>
                                                    <td>{{ visitor.source }}</td>
                                                    <td>{{ visitor.session_duration }}</td>
                                                </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                                <a href="/export_visitors" class="mt-4 inline-block bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700">Export Visitors as CSV</a>
                            {% else %}
                                <p class="text-gray-600">No visitor data available.</p>
                            {% endif %}
                        </div>
                    </div>
                    <div id="bot-logs-tab" class="tab-content hidden">
                        <div class="bg-white p-8 rounded-xl card">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">Bot Detection Logs</h2>
                            {% if bot_logs %}
                                <div class="table-container">
                                    <table>
                                        <thead>
                                            <tr class="bg-gray-200">
                                                <th>Timestamp</th>
                                                <th>IP</th>
                                                <th>Block Reason</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for log in bot_logs %}
                                                <tr class="bot">
                                                    <td>{{ log.timestamp|datetime }}</td>
                                                    <td>{{ log.ip }}</td>
                                                    <td>{{ log.block_reason }}</td>
                                                </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            {% else %}
                                <p class="text-gray-600">No bot detections logged.</p>
                            {% endif %}
                        </div>
                    </div>
                   <div id="access-logs-tab" class="tab-content hidden">
                        <div class="bg-white p-8 rounded-xl card">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">Link Access Logs</h2>
                            {% if access_logs %}
                                <div class="table-container">
                                    <table>
                                        <thead>
                                            <tr class="bg-gray-200">
                                                <th>URL ID</th>
                                                <th>Timestamp</th>
                                                <th>IP</th>
                                                <th>Success</th>
                                                <th>Reason</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% for log in access_logs %}
                                                <tr class="{% if not log.success %}bot{% endif %}">
                                                    <td>{{ log.url_id }}</td>
                                                    <td>{{ log.timestamp|datetime }}</td>
                                                    <td>{{ log.ip }}</td>
                                                    <td>{{ 'Yes' if log.success else 'No' }}</td>
                                                    <td>{{ log.reason }}</td>
                                                </tr>
                                            {% endfor %}
                                        </tbody>
                                    </table>
                                </div>
                            {% else %}
                                <p class="text-gray-600">No access logs available.</p>
                            {% endif %}
                        </div>
                    </div>
                    <div id="analytics-tab" class="tab-content hidden">
                        <div class="bg-white p-8 rounded-xl card">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">Traffic Analytics</h2>
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <h3 class="text-lg font-semibold mb-4">Traffic Sources</h3>
                                    <canvas id="traffic-source-chart"></canvas>
                                    <button onclick="exportChartAsPNG('traffic-source-chart', 'traffic_sources.png')" class="mt-2 bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700">Export as PNG</button>
                                    <button onclick="exportChartAsCSV({{ traffic_sources_values|tojson }}, {{ traffic_sources_keys|tojson }}, 'traffic_sources.csv')" class="mt-2 bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700">Export as CSV</button>
                                    <script>
                                        try {
                                            new Chart(document.getElementById('traffic-source-chart'), {
                                                type: 'pie',
                                                data: {
                                                    labels: {{ traffic_sources_keys|tojson }},
                                                    datasets: [{
                                                        data: {{ traffic_sources_values|tojson }},
                                                        backgroundColor: ['#4f46e5', '#7c3aed']
                                                    }]
                                                },
                                                options: {
                                                    responsive: true,
                                                    plugins: { legend: { position: 'top' } }
                                                }
                                            });
                                        } catch (e) {
                                            console.error('Traffic source chart error:', e);
                                        }
                                    </script>
                                </div>
                                <div>
                                    <h3 class="text-lg font-semibold mb-4">Bot vs Human Ratio</h3>
                                    <canvas id="bot-ratio-chart"></canvas>
                                    <button onclick="exportChartAsPNG('bot-ratio-chart', 'bot_ratio.png')" class="mt-2 bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700">Export as PNG</button>
                                    <button onclick="exportChartAsCSV({{ bot_ratio_values|tojson }}, {{ bot_ratio_keys|tojson }}, 'bot_ratio.csv')" class="mt-2 bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700">Export as CSV</button>
                                    <script>
                                        try {
                                            new Chart(document.getElementById('bot-ratio-chart'), {
                                                type: 'doughnut',
                                                data: {
                                                    labels: {{ bot_ratio_keys|tojson }},
                                                    datasets: [{
                                                        data: {{ bot_ratio_values|tojson }},
                                                        backgroundColor: ['#10b981', '#ef4444']
                                                    }]
                                                },
                                                options: {
                                                    responsive: true,
                                                    plugins: { legend: { position: 'top' } }
                                                }
                                            });
                                        } catch (e) {
                                            console.error('Bot ratio chart error:', e);
                                        }
                                    </script>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        """, username=username, urls=urls, visitors=visitors, bot_logs=bot_logs, access_logs=access_logs,
           traffic_sources_keys=traffic_sources_keys, traffic_sources_values=traffic_sources_values,
           bot_ratio_keys=bot_ratio_keys, bot_ratio_values=bot_ratio_values,
           primary_color=primary_color, error=error, success=success, valkey_error=valkey_error,
           form=form, now=int(time.time()))
    except Exception as e:
        logger.error(f"Dashboard error for user {username}: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                    <p class="text-gray-600">Please try again later or contact support.</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

class DeleteForm(FlaskForm):
    submit = SubmitField('Delete')

class ClearViewsForm(FlaskForm):
    submit = SubmitField('Clear Views')

class ToggleForm(FlaskForm):
    submit = SubmitField('Toggle')

@app.route("/export_visitors", methods=["GET"])
@login_required
def export_visitors():
    try:
        username = session['username']
        logger.debug(f"Exporting visitors for user: {username}")
        max_retries = 2
        visitor_keys = []
        for attempt in range(max_retries):
            try:
                visitor_keys = valkey_client.keys(f"user:{username}:visitor:*")
                logger.debug(f"Found {len(visitor_keys)} visitor keys for user: {username}")
                break
            except Exception as e:
                logger.error(f"Valkey error fetching visitor keys on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
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
                            <p class="text-gray-600">Database error. Unable to export data.</p>
                        </div>
                    </body>
                    </html>
                """), 500
        visitor_data = []
        for key in visitor_keys:
            try:
                visitor = valkey_client.hgetall(key)
                visitor_data.append(visitor)
            except Exception as e:
                logger.error(f"Error processing visitor key {key}: {str(e)}")
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'IP', 'Country', 'Region', 'City', 'Lat', 'Lon', 'ISP', 'Timezone', 'Device', 'Application', 'User Agent', 'Bot Status', 'Block Reason', 'Source', 'Session Duration (s)'])
        for visitor in visitor_data:
            decrypted_ip = decrypt_signed_token(visitor.get('ip', encrypt_signed_token('Unknown')))
            decrypted_ua = decrypt_signed_token(visitor.get('user_agent', encrypt_signed_token('Unknown')))
            writer.writerow([
                datetime.fromtimestamp(int(visitor.get('timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S JST') if visitor.get('timestamp') else 'Unknown',
                decrypted_ip,
                visitor.get('country', 'Unknown'),
                visitor.get('region', 'Unknown'),
                visitor.get('city', 'Unknown'),
                visitor.get('lat', '0.0'),
                visitor.get('lon', '0.0'),
                visitor.get('isp', 'Unknown'),
                visitor.get('timezone', 'Unknown'),
                visitor.get('device', 'Unknown'),
                visitor.get('application', 'Unknown'),
                decrypted_ua,
                visitor.get('bot_status', 'Unknown'),
                visitor.get('block_reason', 'N/A'),
                visitor.get('source', 'direct'),
                visitor.get('session_duration', '0')
            ])
        output.seek(0)
        logger.debug(f"Exported visitor CSV for user: {username}")
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={"Content-Disposition": f"attachment;filename=visitors_{username}.csv"}
        )
    except Exception as e:
        logger.error(f"Error in export_visitors: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/export/<int:index>", methods=["GET"])
@login_required
def export(index):
    try:
        username = session['username']
        logger.debug(f"Exporting data for user: {username}, index: {index}")
        max_retries = 2
        url_keys = []
        for attempt in range(max_retries):
            try:
                url_keys = valkey_client.keys(f"user:{username}:url:*")
                logger.debug(f"Found {len(url_keys)} URL keys for user: {username}")
                break
            except Exception as e:
                logger.error(f"Valkey error fetching URL keys on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
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
                            <p class="text-gray-600">Database error. Unable to export data.</p>
                        </div>
                    </body>
                    </html>
                """), 500
        if index <= 0 or index > len(url_keys):
            logger.warning(f"Invalid export index {index} for user {username}")
            abort(404, "URL not found")
        key = url_keys[index-1]
        url_id = key.split(':')[-1]
        visits = []
        for attempt in range(max_retries):
            try:
                visits = valkey_client.lrange(f"user:{username}:url:{url_id}:visits", 0, -1)
                logger.debug(f"Found {len(visits)} visits for URL ID: {url_id}")
                break
            except Exception as e:
                logger.error(f"Valkey error fetching visits for URL {url_id} on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
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
                            <p class="text-gray-600">Database error. Unable to export data.</p>
                        </div>
                    </body>
                    </html>
                """), 500
        visit_data = []
        for v in visits:
            try:
                visit_data.append(json.loads(v))
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding visit data: {str(e)}")
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'IP', 'Device', 'App', 'Type', 'Country', 'City'])
        for visit in visit_data:
            writer.writerow([
                datetime.fromtimestamp(visit.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S JST') if visit.get('timestamp') else 'Unknown',
                decrypt_signed_token(visit.get('ip', encrypt_signed_token('Unknown'))),
                visit.get('device', 'Unknown'),
                visit.get('app', 'Unknown'),
                visit.get('type', 'Unknown'),
                visit.get('location', {}).get('country', 'Unknown'),
                visit.get('location', {}).get('city', 'Unknown')
            ])
        output.seek(0)
        logger.debug(f"Exported CSV for URL ID: {url_id}")
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={"Content-Disposition": f"attachment;filename=visits_{url_id}.csv"}
        )
    except Exception as e:
        logger.error(f"Error in export: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/delete_url/<url_id>", methods=["POST"])
@login_required
def delete_url(url_id):
    form = DeleteForm()
    if not form.validate_on_submit():
        logger.warning(f"CSRF validation failed for delete_url: {url_id}")
        abort(403, "Invalid CSRF token")
    try:
        username = session['username']
        logger.debug(f"Deleting URL {url_id} for user: {username}")
        max_retries = 2
        for attempt in range(max_retries):
            try:
                valkey_client.delete(f"user:{username}:url:{url_id}")
                valkey_client.delete(f"user:{username}:url:{url_id}:visits")
                valkey_client.delete(f"user:{username}:url:{url_id}:access:*")
                logger.info(f"Deleted URL {url_id} for user: {username}")
                return redirect(url_for('dashboard'))
            except Exception as e:
                logger.error(f"Valkey error deleting URL {url_id} on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
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
                            <p class="text-gray-600">Failed to delete URL. Please try again.</p>
                        </div>
                    </body>
                    </html>
                """), 500
    except Exception as e:
        logger.error(f"Error in delete_url: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/clear_views/<url_id>", methods=["POST"])
@login_required
def clear_views(url_id):
    form = ClearViewsForm()
    if not form.validate_on_submit():
        logger.warning(f"CSRF validation failed for clear_views: {url_id}")
        abort(403, "Invalid CSRF token")
    try:
        username = session['username']
        logger.debug(f"Clearing views for URL {url_id} for user: {username}")
        max_retries = 2
        for attempt in range(max_retries):
            try:
                valkey_client.delete(f"user:{username}:url:{url_id}:visits")
                valkey_client.hset(f"user:{username}:url:{url_id}", "clicks", 0)
                logger.info(f"Cleared views for URL {url_id} for user: {username}")
                return redirect(url_for('dashboard'))
            except Exception as e:
                logger.error(f"Valkey error clearing views for URL {url_id} on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
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
                            <p class="text-gray-600">Failed to clear views. Please try again.</p>
                        </div>
                    </body>
                    </html>
                """), 500
    except Exception as e:
        logger.error(f"Error in clear_views: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/toggle_url/<url_id>", methods=["POST"])
@login_required
def toggle_url(url_id):
    form = ToggleForm()
    if not form.validate_on_submit():
        logger.warning(f"CSRF validation failed for toggle_url: {url_id}")
        abort(403, "Invalid CSRF token")
    try:
        username = session['username']
        logger.debug(f"Toggling URL {url_id} for user: {username}")
        max_retries = 2
        for attempt in range(max_retries):
            try:
                current_status = valkey_client.hget(f"user:{username}:url:{url_id}", "disabled")
                new_status = '0' if current_status == '1' else '1'
                valkey_client.hset(f"user:{username}:url:{url_id}", "disabled", new_status)
                logger.info(f"Toggled URL {url_id} to {'disabled' if new_status == '1' else 'enabled'} for user: {username}")
                return redirect(url_for('dashboard'))
            except Exception as e:
                logger.error(f"Valkey error toggling URL {url_id} on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
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
                            <p class="text-gray-600">Failed to toggle URL. Please try again.</p>
                        </div>
                    </body>
                    </html>
                """), 500
    except Exception as e:
        logger.error(f"Error in toggle_url: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/challenge", methods=["POST"])
def challenge():
    try:
        logger.debug(f"Challenge request received from IP: {request.remote_addr}")
        data = request.get_json()
        if not data or 'challenge' not in data or not isinstance(data['challenge'], (int, float)):
            logger.warning(f"Invalid JS challenge from IP: {request.remote_addr}")
            return {"status": "denied"}, 403
        session_key = f"user:session:{request.remote_addr}"
        valkey_client.setex(session_key, 3600, "1")
        logger.debug(f"JS verification set for IP: {request.remote_addr}")
        return {"status": "ok"}, 200
    except Exception as e:
        logger.error(f"Error in challenge: {str(e)}", exc_info=True)
        return {"status": "error"}, 500

@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    try:
        logger.debug(f"Fingerprint request received from IP: {request.remote_addr}")
        data = request.get_json()
        if data and 'fingerprint' in data:
            fingerprint = generate_fingerprint()
            valkey_client.setex(f"fingerprint:{fingerprint}", 3600, data['fingerprint'])
            logger.debug(f"Fingerprint stored: {fingerprint[:10]}... for IP: {request.remote_addr}")
        return {"status": "ok"}, 200
    except Exception as e:
        logger.error(f"Error in fingerprint: {str(e)}", exc_info=True)
        return {"status": "error"}, 500

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    logger.debug("Favicon requested")
    return "", 204

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"], subdomain="<username>")
@rate_limit(limit=5, per=60)
def redirect_handler(username, endpoint, encrypted_payload, path_segment):
    try:
        base_domain = get_base_domain()
        user_agent = request.headers.get("User-Agent", "")
        ip = request.remote_addr
        headers = request.headers
        referer = headers.get("Referer", "")
        session_start = session.get('session_start', int(time.time()))
        session['session_start'] = session_start
        logger.debug(f"Redirect handler: username={username}, base_domain={base_domain}, endpoint={endpoint}, encrypted_payload={encrypted_payload[:20]}..., path_segment={path_segment}, IP={ip}, User-Agent={user_agent}, URL={request.url}")

        is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, request.path)
        ua = parse(user_agent)
        device = "Desktop"
        if ua.is_mobile:
            device = "Android" if "Android" in user_agent else "iPhone" if "iPhone" in user_agent else "Mobile"
        app = f"{ua.browser.family} {ua.browser.version_string}"[:50] if ua.browser.family else "Unknown"
        visit_type = "Human"
        if is_bot_flag:
            visit_type = "Bot" if "curl/" in user_agent.lower() else "Mimicry" if "Mimicry" in bot_reason else "Bot"
        elif app != "Unknown" and app != f"{ua.browser.family} {ua.browser.version_string}"[:50]:
            visit_type = "App"

        location = get_geoip(ip)
        session_duration = int(time.time()) - session_start
        access_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()

        url_id = hashlib.sha256(request.url.encode()).hexdigest()
        max_retries = 2
        for attempt in range(max_retries):
            try:
                valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                    "timestamp": int(time.time()),
                    "ip": encrypt_signed_token(ip),
                    "success": "0",
                    "reason": "Pending"
                })
                valkey_client.expire(f"user:{username}:url:{url_id}:access:{access_id}", DATA_RETENTION_DAYS * 86400)
                logger.debug(f"Logged access attempt: {access_id} for user: {username}")
                break
            except Exception as e:
                logger.error(f"Valkey error logging access attempt on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue

        if is_bot_flag:
            logger.warning(f"Blocked redirect for IP {ip}: {bot_reason}")
            try:
                valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                    "success": "0",
                    "reason": bot_reason
                })
                bot_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()
                valkey_client.hset(f"user:{username}:bot:{bot_id}", mapping={
                    "timestamp": int(time.time()),
                    "ip": encrypt_signed_token(ip),
                    "user_agent": encrypt_signed_token(user_agent[:100]),
                    "block_reason": bot_reason
                })
                valkey_client.expire(f"user:{username}:bot:{bot_id}", DATA_RETENTION_DAYS * 86400)
                logger.debug(f"Logged bot attempt: {bot_id} for user: {username}")
            except Exception as e:
                logger.error(f"Valkey error updating access or bot log: {str(e)}")
            abort(403, f"Access denied: {bot_reason}")

        url_data = None
        for attempt in range(max_retries):
            try:
                logger.debug(f"Fetching URL data for user:{username}:url:{url_id}, attempt {attempt+1}")
                url_data = valkey_client.hgetall(f"user:{username}:url:{url_id}")
                if not url_data:
                    logger.warning(f"URL {url_id} not found for user {username}")
                    valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                        "success": "0",
                        "reason": "URL not found"
                    })
                    abort(404, "URL not found")
                break
            except Exception as e:
                logger.error(f"Valkey error fetching URL {url_id} on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue
                valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                    "success": "0",
                    "reason": f"Valkey error: {str(e)}"
                })
                return render_template_string("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Database Error</title>
                        <script src="https://cdn.tailwindcss.com"></script>
                    </head>
                    <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                        <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                            <h3 class="text-lg font-bold mb-4 text-red-600">Database Error</h3>
                            <p class="text-gray-600">Unable to access URL data. Please try again later.</p>
                        </div>
                    </body>
                    </html>
                """), 500

        if url_data.get('disabled', '0') == '1':
            logger.warning(f"URL {url_id} is disabled for user {username}")
            valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                "success": "0",
                "reason": "URL disabled"
            })
            abort(403, "URL is disabled")

        for attempt in range(max_retries):
            try:
                visitor_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()
                encrypted_ip = encrypt_signed_token(ip)
                encrypted_ua = encrypt_signed_token(user_agent[:100])
                valkey_client.hset(f"user:{username}:visitor:{visitor_id}", mapping={
                    "timestamp": int(time.time()),
                    "ip": encrypted_ip,
                    "country": location['country'],
                    "region": location['region'],
                    "city": location['city'],
                    "lat": str(location['lat']),
                    "lon": str(location['lon']),
                    "isp": location['isp'],
                    "timezone": location['timezone'],
                    "device": device,
                    "application": app,
                    "user_agent": encrypted_ua,
                    "bot_status": visit_type,
                    "block_reason": bot_reason if is_bot_flag else "N/A",
                    "referer": referer,
                    "source": 'referral' if referer else 'direct',
                    "session_duration": session_duration
                })
                valkey_client.expire(f"user:{username}:visitor:{visitor_id}", DATA_RETENTION_DAYS * 86400)
                logger.debug(f"Logged visitor: {visitor_id} for user: {username}")
                break
            except Exception as e:
                logger.error(f"Valkey error logging visitor on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue

        for attempt in range(max_retries):
            try:
                valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)
                valkey_client.lpush(f"user:{username}:url:{url_id}:visits", json.dumps({
                    "timestamp": int(time.time()),
                    "ip": encrypt_signed_token(ip),
                    "device": device,
                    "app": app,
                    "type": visit_type,
                    "location": location
                }))
                valkey_client.expire(f"user:{username}:url:{url_id}:visits", DATA_RETENTION_DAYS * 86400)
                valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                    "success": "1",
                    "reason": "Access granted"
                })
                logger.debug(f"Logged visit for URL ID: {url_id}")
                break
            except Exception as e:
                logger.error(f"Valkey error logging visit on attempt {attempt+1}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                    continue

        try:
            encrypted_payload = urllib.parse.unquote(encrypted_payload)
            logger.debug(f"Decoded encrypted_payload: {encrypted_payload[:20]}...")
        except Exception as e:
            logger.error(f"Error decoding encrypted_payload: {str(e)}")
            valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                "success": "0",
                "reason": f"Invalid payload format: {str(e)}"
            })
            abort(400, "Invalid payload format")

        payload = None
        for method in ['heap_x3', 'slugstorm', 'pow', 'signed_token']:
            try:
                logger.debug(f"Attempting decryption with method: {method}")
                if method == 'heap_x3':
                    data = decrypt_heap_x3(encrypted_payload)
                    payload = data['payload']
                    if data['fingerprint'] != generate_fingerprint():
                        logger.warning("Fingerprint mismatch")
                        continue
                elif method == 'slugstorm':
                    data = decrypt_slugstorm(encrypted_payload)
                    payload = data['payload']
                elif method == 'pow':
                    payload = decrypt_pow(encrypted_payload)
                else:
                    payload = decrypt_signed_token(encrypted_payload)
                logger.debug(f"Decryption successful with {method}")
                break
            except Exception as e:
                logger.debug(f"Decryption failed with {method}: {str(e)}")
                continue

        if not payload:
            logger.error("All decryption methods failed")
            valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                "success": "0",
                "reason": "Invalid payload"
            })
            abort(400, "Invalid payload")

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            logger.debug(f"Parsed payload: redirect_url={redirect_url}, expiry={expiry}")
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                    "success": "0",
                    "reason": "Invalid redirect URL"
                })
                abort(400, "Invalid redirect URL")
            if time.time() > expiry:
                logger.warning(f"URL expired: {request.url}")
                try:
                    valkey_client.delete(f"user:{username}:url:{url_id}")
                    valkey_client.delete(f"user:{username}:url:{url_id}:visits")
                    valkey_client.delete(f"user:{username}:url:{url_id}:access:*")
                    logger.info(f"Deleted expired URL: {url_id}")
                except Exception as e:
                    logger.error(f"Valkey error deleting expired URL: {str(e)}")
                valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                    "success": "0",
                    "reason": "URL expired"
                })
                abort(410, "URL has expired")
        except Exception as e:
            logger.error(f"Payload parsing error: {str(e)}")
            valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                "success": "0",
                "reason": f"Invalid payload: {str(e)}"
            })
            abort(400, "Invalid payload")

        final_url = f"{redirect_url.rstrip('/')}/{path_segment}"
        logger.info(f"Redirecting to {final_url}")
        return redirect(final_url, code=302)
    except Exception as e:
        error_message = f"Redirect handler error: {str(e)}"
        logger.error(error_message, exc_info=True)
        try:
            access_id = hashlib.sha256(f"{ip}{time.time()}".encode()).hexdigest()
            valkey_client.hset(f"user:{username}:url:{url_id}:access:{access_id}", mapping={
                "timestamp": int(time.time()),
                "ip": encrypt_signed_token(ip),
                "success": "0",
                "reason": error_message
            })
        except Exception as e2:
            logger.error(f"Valkey error logging failed access: {str(e2)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                    <p class="text-gray-600">Please try again later or contact support.</p>
                </div>
            </body>
            </html>
        """, error=error_message), 500

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"])
@rate_limit(limit=5, per=60)
def redirect_handler_no_subdomain(endpoint, encrypted_payload, path_segment):
    try:
        host = request.host
        username = host.split('.')[0] if '.' in host else "default"
        logger.debug(f"Fallback redirect handler: username={username}, endpoint={endpoint}, encrypted_payload={encrypted_payload[:20]}..., path_segment={path_segment}, URL={request.url}")
        return redirect_handler(username, endpoint, encrypted_payload, path_segment)
    except Exception as e:
        logger.error(f"Error in redirect_handler_no_subdomain: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                    <p class="text-gray-600">Please try again later or contact support.</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/denied", methods=["GET"])
def denied():
    try:
        logger.debug("Access denied page accessed")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="robots" content="noindex, nofollow">
                <title>Access Denied</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Access Denied</h3>
                    <p class="text-gray-600">Suspicious activity detected.</p>
                </div>
            </body>
            </html>
        """), 403
    except Exception as e:
        logger.error(f"Error in denied: {str(e)}")
        return "Access Denied", 403

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.warning(f"404 Not Found: path={path}, host={request.host}, url={request.url}")
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Not Found</title>
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
    """), 404

def generate_random_string(length):
    try:
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        result = "".join(secrets.choice(characters) for _ in range(length))
        logger.debug(f"Generated random string: {result[:10]}...")
        return result
    except Exception as e:
        logger.error(f"Error generating random string: {str(e)}")
        return secrets.token_hex(length // 2)

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}", exc_info=True)
        import sys
        sys.exit(1)
