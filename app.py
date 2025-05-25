from flask import Flask, request, redirect, render_template_string, abort, url_for, session, jsonify, Response
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

# Environment variables
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", secrets.token_bytes(32))
VALKEY_HOST = os.getenv("VALKEY_HOST", "valkey-137d99b9-reign.e.aivencloud.com")
VALKEY_PORT = int(os.getenv("VALKEY_PORT", 25708))
VALKEY_USERNAME = os.getenv("VALKEY_USERNAME", "default")
VALKEY_PASSWORD = os.getenv("VALKEY_PASSWORD", "AVNS_Yzfa75IOznjCrZJIyzI")
USER_TXT_URL = os.getenv("USER_TXT_URL", "https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt")
DATA_RETENTION_DAYS = int(os.getenv("DATA_RETENTION_DAYS", 90))
GEOIP_PROVIDER = os.getenv("GEOIP_PROVIDER", "ipapi")

# Log key for debugging
logger.debug(f"ENCRYPTION_KEY hash: {hashlib.sha256(ENCRYPTION_KEY).hexdigest()[:10]}...")

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

# Configuration
try:
    app.config['SECRET_KEY'] = FLASK_SECRET_KEY
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
    logger.debug("Flask configuration set successfully")
except Exception as e:
    logger.error(f"Error setting Flask config: {str(e)}", exc_info=True)
    raise

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
            logger.debug(f"IP {ip} allowed for generated link {endpoint}, skipping JS verification")
            return False, "Generated link access"
        if not user_agent:
            logger.warning(f"Blocked IP {ip}: No User-Agent provided")
            return True, "Missing User-Agent"
        user_agent_lower = user_agent.lower()
        for pattern in BOT_PATTERNS:
            if pattern in user_agent_lower:
                logger.warning(f"Blocked IP {ip}: Known bot pattern {pattern}")
                return True, f"Known bot: {pattern}"
        if 'HeadlessChrome' in user_agent or 'PhantomJS' in user_agent:
            logger.warning(f"Blocked IP {ip}: Headless browser detected")
            return True, "Headless browser"
        if valkey_client:
            try:
                key = f"bot_check:{ip}"
                count = valkey_client.get(key)
                if count and int(count) > 10:
                    logger.warning(f"Blocked IP {ip}: Rapid requests")
                    return True, "Rapid requests"
                valkey_client.incr(key)
                valkey_client.expire(key, 60)
            except Exception as e:
                logger.error(f"Valkey error in bot check: {str(e)}")
        if ip.startswith(('162.249.', '5.62.', '84.39.')):
            logger.warning(f"Blocked IP {ip}: Data center IP range")
            return True, "Data center IP"
        if endpoint == "/login" and headers.get('Referer') and 'Mozilla' in user_agent:
            logger.debug(f"IP {ip} allowed for /login with valid headers")
            return False, "Likely human (login attempt)"
        if 'js_verified' not in session:
            logger.warning(f"Blocked IP {ip}: Missing JS verification")
            return True, "Missing JS verification"
        return False, "Human"
    except Exception as e:
        logger.error(f"Error in is_bot for IP {ip}: {str(e)}")
        return True, "Error in bot detection"

def check_asn(ip):
    try:
        logger.debug("Skipping ASN check (no MaxMind key)")
        return False
    except Exception as e:
        logger.error(f"ASN check failed for IP {ip}: {str(e)}")
        return False

def get_geoip(ip):
    try:
        if valkey_client:
            cache_key = f"geoip:{ip}"
            cached = valkey_client.get(cache_key)
            if cached:
                logger.debug(f"GeoIP cache hit for IP {ip}")
                return json.loads(cached)
        if GEOIP_PROVIDER == "ip-api":
            response = requests.get(f"https://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
            response.raise_for_status()
            data = response.json()
            if data.get('status') != 'success':
                logger.error(f"ip-api.com error for IP {ip}: {data.get('message', 'Unknown error')}")
                return {"country": "Unknown", "city": "Unknown", "region": "Unknown", "lat": 0.0, "lon": 0.0, "isp": "Unknown", "timezone": "Unknown"}
            geo_data = {
                "country": data.get('country', 'Unknown'),
                "city": data.get('city', 'Unknown'),
                "region": data.get('regionName', 'Unknown'),
                "lat": data.get('lat', 0.0),
                "lon": data.get('lon', 0.0),
                "isp": data.get('isp', 'Unknown'),
                "timezone": data.get('timezone', 'Unknown')
            }
        else:
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            response.raise_for_status()
            data = response.json()
            if data.get('error'):
                logger.error(f"ipapi.co error for IP {ip}: {data.get('reason', 'Unknown error')}")
                return {"country": "Unknown", "city": "Unknown", "region": "Unknown", "lat": 0.0, "lon": 0.0, "isp": "Unknown", "timezone": "Unknown"}
            geo_data = {
                "country": data.get('country_name', 'Unknown'),
                "city": data.get('city', 'Unknown'),
                "region": data.get('region', 'Unknown'),
                "lat": data.get('latitude', 0.0),
                "lon": data.get('longitude', 0.0),
                "isp": data.get('org', 'Unknown'),
                "timezone": data.get('timezone', 'Unknown')
            }
        if valkey_client:
            try:
                valkey_client.setex(cache_key, 86400, json.dumps(geo_data))
                logger.debug(f"Cached GeoIP for IP {ip}")
            except Exception as e:
                logger.error(f"Valkey error caching GeoIP: {str(e)}")
        return geo_data
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
        fingerprint = hashlib.sha256(raw.encode()).hexdigest()
        logger.debug(f"Generated fingerprint: {fingerprint[:10]}...")
        return fingerprint
    except Exception as e:
        logger.error(f"Error in generate_fingerprint: {str(e)}")
        return hashlib.sha256(str(time.time()).encode()).hexdigest()

def verify_browser():
    try:
        if not valkey_client:
            logger.warning("Valkey unavailable, skipping browser verification")
            return True
        fingerprint = generate_fingerprint()
        session_key = f"browser:{fingerprint}"
        exists = valkey_client.exists(session_key)
        if not exists:
            valkey_client.setex(session_key, 3600, 1)
            logger.debug(f"New browser fingerprint: {fingerprint[:10]}...")
            return False
        logger.debug(f"Browser verified: {fingerprint[:10]}...")
        return True
    except Exception as e:
        logger.error(f"Error in verify_browser: {str(e)}")
        return True

def encrypt_heap_x3(payload, fingerprint):
    try:
        logger.debug(f"heap_x3 input payload: {payload[:50]}..., fingerprint: {fingerprint[:10]}...")
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = json.dumps({"payload": payload, "fingerprint": fingerprint}).encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag
        slug = secrets.token_hex(50)
        result = f"{base64.urlsafe_b64encode(encrypted).decode()}.{slug}"
        logger.debug(f"heap_x3 encrypted: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"heap_x3 encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_heap_x3(encrypted):
    try:
        logger.debug(f"heap_x3 decrypting: {encrypted[:20]}...")
        encrypted, _ = encrypted.split('.')
        encrypted = base64.urlsafe_b64decode(encrypted)
        iv = encrypted[:12]
        tag = encrypted[-16:]
        ciphertext = encrypted[12:-16]
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        result = json.loads(decrypted.decode())
        logger.debug(f"heap_x3 decrypted: {json.dumps(result)[:50]}...")
        return result
    except Exception as e:
        logger.error(f"heap_x3 decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_pow(payload):
    try:
        logger.debug(f"pow input payload: {payload[:50]}...")
        iv = secrets.token_bytes(8)
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = payload.encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        result = base64.urlsafe_b64encode(iv + ciphertext).decode()
        logger.debug(f"pow encrypted: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"pow encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_pow(encrypted):
    try:
        logger.debug(f"pow decrypting: {encrypted[:20]}...")
        encrypted = base64.urlsafe_b64decode(encrypted)
        iv = encrypted[:8]
        ciphertext = encrypted[8:]
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, iv), backend=default_backend())
        decryptor = cipher.decryptor()
        result = (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        logger.debug(f"pow decrypted: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"pow decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_chacha20_poly1305(payload):
    try:
        logger.debug(f"chacha20_poly1305 input payload: {payload[:50]}...")
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, nonce), modes.Poly1305(), backend=default_backend())
        encryptor = cipher.encryptor()
        data = payload.encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        result = base64.urlsafe_b64encode(nonce + tag + ciphertext).decode()
        logger.debug(f"chacha20_poly1305 encrypted: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"chacha20_poly1305 encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_chacha20_poly1305(encrypted):
    try:
        logger.debug(f"chacha20_poly1305 decrypting: {encrypted[:20]}...")
        data = base64.urlsafe_b64decode(encrypted)
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, nonce), modes.Poly1305(tag), backend=default_backend())
        decryptor = cipher.decryptor()
        result = (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        logger.debug(f"chacha20_poly1305 decrypted: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"chacha20_poly1305 decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_aes_gcm_alt(payload):
    try:
        logger.debug(f"aes_gcm_alt input payload: {payload[:50]}...")
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = payload.encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        result = base64.urlsafe_b64encode(iv + encryptor.tag + ciphertext).decode()
        logger.debug(f"aes_gcm_alt encrypted: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"aes_gcm_alt encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_aes_gcm_alt(encrypted):
    try:
        logger.debug(f"aes_gcm_alt decrypting: {encrypted[:20]}...")
        data = base64.urlsafe_b64decode(encrypted)
        iv = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        result = (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        logger.debug(f"aes_gcm_alt decrypted: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"aes_gcm_alt decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_fern128(payload):
    try:
        logger.debug(f"fern128 input payload: {payload[:50]}...")
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        from cryptography.hazmat.primitives.padding import PKCS7
        padder = PKCS7(128).padder()
        padded_data = padder.update(payload.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        result = base64.urlsafe_b64encode(iv + ciphertext).decode()
        logger.debug(f"fern128 encrypted: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"fern128 encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_fern128(encrypted):
    try:
        logger.debug(f"fern128 decrypting: {encrypted[:20]}...")
        data = base64.urlsafe_b64decode(encrypted)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        from cryptography.hazmat.primitives.padding import PKCS7
        unpadder = PKCS7(128).unpadder()
        result = unpadder.update(padded_data) + unpadder.finalize()
        logger.debug(f"fern128 decrypted: {result[:50]}...")
        return result.decode()
    except Exception as e:
        logger.error(f"fern128 decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def get_valid_usernames():
    try:
        if valkey_client:
            cached = valkey_client.get("usernames")
            if cached:
                logger.debug("Retrieved usernames from Valkey cache")
                return json.loads(cached)
        response = requests.get(USER_TXT_URL)
        response.raise_for_status()
        usernames = [line.strip() for line in response.text.splitlines() if line.strip()]
        if valkey_client:
            try:
                valkey_client.setex("usernames", 3600, json.dumps(usernames))
                logger.debug("Cached usernames in Valkey")
            except Exception as e:
                logger.error(f"Valkey error caching usernames: {str(e)}")
        logger.debug(f"Fetched {len(usernames)} usernames")
        return usernames
    except Exception as e:
        logger.error(f"Error fetching user.txt: {str(e)}")
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
            logger.debug(f"Redirecting request to {request.host} to google.com")
            return redirect("https://google.com", code=302)
    except Exception as e:
        logger.error(f"Error in block_ohio_subdomain: {str(e)}")

@app.before_request
def log_visitor():
    try:
        if request.path.startswith(('/static', '/challenge', '/fingerprint', '/denied')):
            return
        username = session.get('username', 'default')
        user_agent = request.headers.get("User-Agent", "")
        ip = request.remote_addr
        headers = request.headers
        referer = headers.get("Referer", "")
        session_start = session.get('session_start', int(time.time()))
        session['session_start'] = session_start
        ua = parse(user_agent)
        device = "Desktop" if not ua.is_mobile else "Android" if "Android" in user_agent else "iPhone" if "iPhone" in user_agent else "Mobile"
        app = "Outlook" if "Outlook" in user_agent else ua.browser.family if ua.browser.family else "Unknown"
        is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, request.path)
        visit_type = "Human"
        if is_bot_flag:
            visit_type = "Bot" if "curl/" in user_agent.lower() else "Mimicry" if "Mimicry" in bot_reason else "Bot"
        elif app != "Unknown" and app != ua.browser.family:
            visit_type = "App"
        location = get_geoip(ip)
        session_duration = int(time.time()) - session_start
        if valkey_client:
            try:
                fingerprint = generate_fingerprint()
                visitor_id = hashlib.sha256(f"{ip}{fingerprint}".encode()).hexdigest()
                if not valkey_client.exists(f"user:{username}:visitor:{visitor_id}"):
                    valkey_client.hset(f"user:{username}:visitor:{visitor_id}", mapping={
                        "timestamp": int(time.time()),
                        "ip": ip,
                        "country": location['country'],
                        "city": location['city'],
                        "region": location['region'],
                        "lat": str(location['lat']),
                        "lon": str(location['lon']),
                        "isp": location['isp'],
                        "timezone": location['timezone'],
                        "device": device,
                        "application": app,
                        "user_agent": user_agent,
                        "bot_status": visit_type,
                        "block_reason": bot_reason if is_bot_flag else "N/A",
                        "referer": referer,
                        "source": 'referral' if referer else 'direct',
                        "session_duration": session_duration
                    })
                    valkey_client.expire(f"user:{username}:visitor:{visitor_id}", DATA_RETENTION_DAYS * 86400)
                    logger.debug(f"Logged visitor: {visitor_id} for user: {username}")
            except Exception as e:
                logger.error(f"Valkey error logging visitor: {str(e)}")
    except Exception as e:
        logger.error(f"Error in log_visitor: {str(e)}")

@app.route("/login", methods=["GET", "POST"])
@rate_limit(limit=5, per=60)
def login():
    try:
        logger.debug(f"Accessing /login, method: {request.method}, next: {request.args.get('next', '')}")
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            logger.debug(f"Login attempt with username: {username}")
            valid_usernames = get_valid_usernames()
            if username in valid_usernames:
                session['username'] = username
                session.permanent = True
                session.modified = True
                logger.debug(f"User {username} logged in")
                next_url = request.form.get('next') or url_for('dashboard')
                logger.debug(f"Redirecting to {next_url}")
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
                            const canvas = document.createElement('canvas');
                            const ctx = canvas.getContext('2d');
                            ctx.textBaseline = 'top';
                            ctx.font = '14px Arial';
                            ctx.fillText('Fingerprint', 2, 2);
                            return canvas.toDataURL();
                        }
                        window.onload = function() {
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
                    <div class="container bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
                        <h1 class="text-3xl font-bold mb-6 text-center text-gray-900">Login</h1>
                        <p class="text-red-600 mb-4 text-center">Invalid username.</p>
                        <form method="POST" class="space-y-5">
                            <input type="hidden" name="next" value="{{ request.args.get('next', '') }}">
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Username</label>
                                <input type="text" name="username" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                            </div>
                            <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700">Login</button>
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
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        ctx.textBaseline = 'top';
                        ctx.font = '14px Arial';
                        ctx.fillText('Fingerprint', 2, 2);
                        return canvas.toDataURL();
                    }
                    window.onload = function() {
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
                <div class="container bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
                    <h1 class="text-3xl font-bold mb-6 text-center text-gray-900">Login</h1>
                    <form method="POST" class="space-y-5">
                        <input type="hidden" name="next" value="{{ request.args.get('next', '') }}">
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Username</label>
                            <input type="text" name="username" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                        </div>
                        <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700">Login</button>
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong.</p>
                </div>
            </body>
            </html>
        """), 500

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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
@rate_limit(limit=5, per=60)
def dashboard():
    try:
        if 'username' not in session:
            logger.error("Session missing username, redirecting to login")
            return redirect(url_for('login'))
        username = session['username']
        logger.debug(f"Accessing dashboard for user: {username}")

        base_domain = get_base_domain()
        error = None

        if request.method == "POST":
            logger.debug(f"Processing POST form data: {request.form}")
            subdomain = request.form.get("subdomain", "default")
            randomstring1 = request.form.get("randomstring1", "default")
            base64email = request.form.get("base64email", "default")
            destination_link = request.form.get("destination_link", "https://example.com")
            randomstring2 = request.form.get("randomstring2", generate_random_string(8))
            analytics_enabled = request.form.get("analytics_enabled", "off") == "on"
            try:
                expiry = int(request.form.get("expiry", 86400))
            except ValueError:
                logger.error("Invalid expiry value, defaulting to 86400")
                expiry = 86400

            if not re.match(r"^https?://", destination_link):
                error = "Invalid URL"
                logger.warning(f"Invalid destination_link: {destination_link}")
            elif not (2 <= len(subdomain) <= 100 and re.match(r"^[A-Za-z0-9-]{2,100}$", subdomain)):
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
                base64_email = base64email
                path_segment = f"{randomstring1}{base64_email}{randomstring2}"
                endpoint = generate_random_string(8)
                encryption_methods = ['heap_x3', 'pow', 'chacha20_poly1305', 'aes_gcm_alt', 'fern128']
                method = secrets.choice(encryption_methods)
                logger.debug(f"Selected encryption method: {method}")
                fingerprint = generate_fingerprint()
                expiry_timestamp = int(time.time()) + expiry
                try:
                    payload = json.dumps({
                        "student_link": destination_link,
                        "timestamp": int(time.time() * 1000),
                        "randomstring1": randomstring1,
                        "randomstring2": randomstring2,
                        "expiry": expiry_timestamp
                    })
                    logger.debug(f"Raw payload: {payload[:50]}...")
                except Exception as e:
                    logger.error(f"Payload JSON error: {str(e)}")
                    error = "Invalid payload data"

                if not error:
                    try:
                        if method == 'heap_x3':
                            encrypted_payload = encrypt_heap_x3(payload, fingerprint)
                        elif method == 'pow':
                            encrypted_payload = encrypt_pow(payload)
                        elif method == 'chacha20_poly1305':
                            encrypted_payload = encrypt_chacha20_poly1305(payload)
                        elif method == 'aes_gcm_alt':
                            encrypted_payload = encrypt_aes_gcm_alt(payload)
                        else:
                            encrypted_payload = encrypt_fern128(payload)
                        logger.debug(f"Encrypted payload: {encrypted_payload[:50]}...")
                    except Exception as e:
                        logger.error(f"Encryption failed with {method}: {str(e)}")
                        error = "Failed to encrypt payload"

                if not error:
                    try:
                        quoted_subdomain = urllib.parse.quote(subdomain, safe='')
                        quoted_payload = urllib.parse.quote(encrypted_payload, safe='')
                        quoted_path = urllib.parse.quote(path_segment, safe='')
                        generated_url = f"https://{quoted_subdomain}.{base_domain}/{endpoint}/{quoted_payload}/{quoted_path}"
                        logger.debug(f"Generated URL: {generated_url[:100]}...")
                        url_id = hashlib.sha256(generated_url.encode()).hexdigest()
                    except Exception as e:
                        logger.error(f"URL generation error: {str(e)}")
                        error = "Failed to generate URL"

                if not error and valkey_client:
                    try:
                        valkey_client.hset(f"user:{username}:url:{url_id}", mapping={
                            "url": generated_url,
                            "destination": destination_link,
                            "path_segment": path_segment,
                            "created": int(time.time()),
                            "expiry": expiry_timestamp,
                            "clicks": 0,
                            "analytics_enabled": "1" if analytics_enabled else "0"
                        })
                        valkey_client.expire(f"user:{username}:url:{url_id}", DATA_RETENTION_DAYS * 86400)
                        logger.info(f"Stored URL for {username}: {generated_url}")
                    except Exception as e:
                        logger.error(f"Valkey error storing URL: {str(e)}")
                        error = "Failed to store URL"
                elif not valkey_client:
                    logger.warning("Valkey unavailable")
                    error = "Database unavailable"

                if not error:
                    logger.debug("URL generation successful")
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
                        visits = valkey_client.lrange(f"{key}:visits", 0, -1)
                        visit_data = []
                        human_visits = 0
                        bot_visits = 0
                        for v in visits:
                            try:
                                visit = json.loads(v)
                                visit_data.append(visit)
                                if visit.get('type') == 'Human':
                                    human_visits += 1
                                else:
                                    bot_visits += 1
                            except json.JSONDecodeError as e:
                                logger.error(f"Error decoding visit data: {str(e)}")
                        click_trends = {}
                        for visit in visit_data:
                            try:
                                date = datetime.fromtimestamp(visit.get('timestamp', 0)).strftime('%Y-%m-%d')
                                click_trends[date] = click_trends.get(date, 0) + 1
                            except (KeyError, ValueError) as e:
                                logger.error(f"Error processing visit timestamp: {str(e)}")
                        urls.append({
                            "url": url_data.get('url', ''),
                            "destination": url_data.get('destination', ''),
                            "path_segment": url_data.get('path_segment', ''),
                            "created": datetime.fromtimestamp(int(url_data.get('created', 0))).strftime('%Y-%m-%d %H:%M:%S') if url_data.get('created') else 'Unknown',
                            "expiry": datetime.fromtimestamp(int(url_data.get('expiry', 0))).strftime('%Y-%m-%d %H:%M:%S') if url_data.get('expiry') else 'Unknown',
                            "clicks": int(url_data.get('clicks', 0)) if url_data.get('clicks') else 0,
                            "analytics_enabled": url_data.get('analytics_enabled', '0') == '1',
                            "visits": visit_data,
                            "human_visits": human_visits,
                            "bot_visits": bot_visits,
                            "click_trends_keys": list(click_trends.keys()),
                            "click_trends_values": list(click_trends.values()),
                            "url_id": url_id
                        })
                    except Exception as e:
                        logger.error(f"Error processing URL key {key}: {str(e)}")
            except Exception as e:
                logger.error(f"Valkey error fetching URLs: {str(e)}")
                valkey_error = "Unable to fetch URL history"
        else:
            logger.warning("Valkey unavailable")
            valkey_error = "Database unavailable"

        visitors = []
        bot_logs = []
        traffic_sources = {"direct": 0, "referral": 0, "organic": 0}
        bot_ratio = {"human": 0, "bot": 0}
        visitor_index = 1
        if valkey_client:
            try:
                logger.debug(f"Fetching visitor keys for user: {username}")
                visitor_keys = valkey_client.keys(f"user:{username}:visitor:*")
                logger.debug(f"Found {len(visitor_keys)} visitor keys")
                visitor_data = []
                for key in visitor_keys:
                    try:
                        data = valkey_client.hgetall(key)
                        if not data:
                            logger.warning(f"Empty visitor data for key {key}")
                            continue
                        visitor_data.append((int(data.get('timestamp', 0)), data))
                    except Exception as e:
                        logger.error(f"Error processing visitor key {key}: {str(e)}")
                visitor_data.sort(key=lambda x: x[0], reverse=True)
                for _, visitor_data in visitor_data:
                    source = 'referral' if visitor_data.get('referer') else 'direct'
                    visitors.append({
                        "index": visitor_index,
                        "timestamp": datetime.fromtimestamp(int(visitor_data.get('timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S') if visitor_data.get('timestamp') else 'Unknown',
                        "ip": visitor_data.get('ip', 'Unknown'),
                        "country": visitor_data.get('country', 'Unknown'),
                        "region": visitor_data.get('region', 'Unknown'),
                        "city": visitor_data.get('city', 'Unknown'),
                        "lat": float(visitor_data.get('lat', 0.0)),
                        "lon": float(visitor_data.get('lon', 0.0)),
                        "isp": visitor_data.get('isp', 'Unknown'),
                        "timezone": visitor_data.get('timezone', 'Unknown'),
                        "device": visitor_data.get('device', 'Unknown'),
                        "application": visitor_data.get('application', 'Unknown'),
                        "user_agent": visitor_data.get('user_agent', 'Unknown'),
                        "bot_status": visitor_data.get('bot_status', 'Unknown'),
                        "block_reason": visitor_data.get('block_reason', 'N/A'),
                        "source": source,
                        "session_duration": int(visitor_data.get('session_duration', 0))
                    })
                    visitor_index += 1
                    if visitor_data.get('bot_status') != 'Human':
                        bot_logs.append({
                            "timestamp": visitor_data.get('timestamp', 'Unknown'),
                            "ip": visitor_data.get('ip', 'Unknown'),
                            "block_reason": visitor_data.get('block_reason', 'Unknown')
                        })
                        bot_ratio['bot'] += 1
                    else:
                        bot_ratio['human'] += 1
                    traffic_sources[source] = traffic_sources.get(source, 0) + 1
            except Exception as e:
                logger.error(f"Valkey error fetching visitors: {str(e)}")
                valkey_error = "Unable to fetch visitor data"
        else:
            logger.warning("Valkey unavailable")
            valkey_error = "Database unavailable"

        try:
            traffic_sources_keys = list(traffic_sources.keys())
            traffic_sources_values = list(traffic_sources.values())
            bot_ratio_keys = list(bot_ratio.keys())
            bot_ratio_values = list(bot_ratio.values())
            logger.debug(f"Traffic sources: {traffic_sources}, Bot ratio: {bot_ratio}")
        except Exception as e:
            logger.error(f"Error preparing chart data: {str(e)}")
            traffic_sources_keys = ["direct", "referral", "organic"]
            traffic_sources_values = [0, 0, 0]
            bot_ratio_keys = ["human", "bot"]
            bot_ratio_values = [0, 0]

        theme_seed = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:6]
        primary_color = f"#{theme_seed}"

        logger.debug(f"Rendering dashboard template for user: {username}")
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
                    .bot { background: #fee2e2; }
                    .refresh-btn { animation: pulse 2s infinite; }
                    @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }
                    .toggle-switch { position: relative; display: inline-block; width: 60px; height: 34px; }
                    .toggle-switch input { opacity: 0; width: 0; height: 0; }
                    .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
                    .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
                    input:checked + .slider { background-color: #4f46e5; }
                    input:checked + .slider:before { transform: translateX(26px); }
                </style>
                <script>
                    function toggleAnalytics(id) {
                        document.getElementById('analytics-' + id).classList.toggle('hidden');
                    }
                    function applyFilters(id) {
                        let device = document.getElementById('filter-device-' + id).value;
                        let type = document.getElementById('filter-type-' + id).value;
                        let rows = document.querySelectorAll('#visits-' + id + ' tr');
                        rows.forEach(row => {
                            let deviceCell = row.cells[2].textContent;
                            let typeCell = row.cells[4].textContent;
                            row.style.display = (
                                (device === '' || deviceCell.includes(device)) &&
                                (type === '' || typeCell.includes(type))
                            ) ? '' : 'none';
                        });
                    }
                    function showTab(tabId) {
                        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.add('hidden'));
                        document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
                        document.getElementById(tabId).classList.remove('hidden');
                        document.querySelector(`[onclick="showTab('${tabId}')"]`).classList.add('active');
                    }
                    function refreshDashboard() {
                        window.location.reload();
                    }
                    function toggleAnalyticsSwitch(urlId, index) {
                        fetch('/toggle_analytics/' + urlId, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' }
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
                    <h1 class="text-4xl font-bold mb-8 text-center text-white">Welcome, {{ username }}</h1>
                    {% if error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ error }}</p>
                    {% endif %}
                    {% if valkey_error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ valkey_error }}</p>
                    {% endif %}
                    <div class="flex space-x-4 mb-4">
                        <button class="tab px-4 py-2 bg-white rounded-lg active" onclick="showTab('urls-tab')">URLs</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('visitors-tab')">Visitor Views</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('bot-logs-tab')">Bot Logs</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('analytics-tab')">Analytics</button>
                    </div>
                    <div id="urls-tab" class="tab-content">
                        <div class="bg-white p-8 rounded-lg card mb-8">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">Generate New URL</h2>
                            <form method="POST" class="space-y-5">
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Subdomain</label>
                                    <input type="text" name="subdomain" required minlength="2" maxlength="100" pattern="[A-Za-z0-9-]{2,100}" title="Subdomain must be 2-100 characters (letters, numbers, or hyphens)" class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Randomstring1</label>
                                    <input type="text" name="randomstring1" required minlength="2" maxlength="100" pattern="[A-Za-z0-9_@.]{2,100}" title="Randomstring1 must be 2-100 characters (letters, numbers, _, @, .)" class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Base64emailInput</label>
                                    <input type="text" name="base64email" required minlength="2" maxlength="100" pattern="[A-Za-z0-9_@.]{2,100}" title="Base64email must be 2-100 characters (letters, numbers, _, @, .)" class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Destination Link</label>
                                    <input type="url" name="destination_link" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Randomstring2</label>
                                    <input type="text" name="randomstring2" required minlength="2" maxlength="100" pattern="[A-Za-z0-9_@.]{2,100}" title="Randomstring2 must be 2-100 characters (letters, numbers, _, @, .)" class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Expiry</label>
                                    <select name="expiry" class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300">
                                        <option value="3600">1 Hour</option>
                                        <option value="86400" selected>1 Day</option>
                                        <option value="604800">1 Week</option>
                                        <option value="2592000">1 Month</option>
                                    </select>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Enable Analytics</label>
                                    <input type="checkbox" name="analytics_enabled" class="mt-1 p-3">
                                </div>
                                <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700">Generate URL</button>
                            </form>
                        </div>
                        <div class="bg-white p-8 rounded-lg card">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">URL History</h2>
                            {% if urls %}
                                {% for url in urls %}
                                    <div class="card bg-gray-50 p-6 rounded-lg mb-4">
                                        <h3 class="text-xl font-semibold text-gray-900">{{ url.destination }}</h3>
                                        <p class="text-gray-600 break-all"><strong>URL:</strong> <a href="{{ url.url }}" target="_blank" class="text-indigo-600">{{ url.url }}</a></p>
                                        <p class="text-gray-600"><strong>Path Segment:</strong> {{ url.path_segment }}</p>
                                        <p class="text-gray-600"><strong>Created:</strong> {{ url.created }}</p>
                                        <p class="text-gray-600"><strong>Expires:</strong> {{ url.expiry }}</p>
                                        <p class="text-gray-600"><strong>Total Clicks:</strong> {{ url.clicks }}</p>
                                        <p class="text-gray-600"><strong>Human Clicks:</strong> {{ url.human_visits }}</p>
                                        <p class="text-gray-600"><strong>Bot Clicks:</strong> {{ url.bot_visits }}</p>
                                        <div class="flex items-center mt-2">
                                            <label class="text-sm font-medium text-gray-700 mr-2">Analytics:</label>
                                            <label class="toggle-switch">
                                                <input type="checkbox" id="analytics-toggle-{{ loop.index }}" {% if url.analytics_enabled %}checked{% endif %} onchange="toggleAnalyticsSwitch('{{ url.url_id }}', '{{ loop.index }}')">
                                                <span class="slider"></span>
                                            </label>
                                        </div>
                                        <div class="mt-2 flex space-x-2">
                                            <button onclick="toggleAnalytics('{{ loop.index }}')" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700">Toggle Analytics</button>
                                            <a href="/clear_views/{{ url.url_id }}" class="bg-yellow-600 text-white px-4 py-2 rounded-lg hover:bg-yellow-700" onclick="return confirm('Are you sure you want to clear all views for this URL?')">Clear Views</a>
                                            <a href="/delete_url/{{ url.url_id }}" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700" onclick="return confirm('Are you sure you want to delete this URL?')">Delete URL</a>
                                        </div>
                                        <div id="analytics-{{ loop.index }}" class="hidden mt-4">
                                            <h4 class="text-lg font-semibold text-gray-900">Visitor Analytics</h4>
                                            <canvas id="chart-{{ loop.index }}" class="mt-4"></canvas>
                                            <script>
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
                                                <table>
                                                    <thead>
                                                        <tr class="bg-gray-200">
                                                            <th>Timestamp</th>
                                                            <th>IP</th>
                                                            <th>Device</th>
                                                            <th>App</th>
                                                            <th>Type</th>
                                                            <th>Country</th>
                                                            <th>Region</th>
                                                            <th>City</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody id="visits-{{ loop.index }}">
                                                        {% for visit in url.visits %}
                                                            <tr class="{% if visit.type != 'Human' %}bot{% endif %}">
                                                                <td>{{ visit.timestamp|datetime }}</td>
                                                                <td>{{ visit.ip }}</td>
                                                                <td>{{ visit.device }}</td>
                                                                <td>{{ visit.app }}</td>
                                                                <td>{{ visit.type }}</td>
                                                                <td>{{ visit.location.country }}</td>
                                                                <td>{{ visit.location.region }}</td>
                                                                <td>{{ visit.location.city }}</td>
                                                            </tr>
                                                        {% endfor %}
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
                        <div class="bg-white p-8 rounded-lg card">
                            <div class="flex justify-between items-center mb-4">
                                <h2 class="text-2xl font-bold text-gray-900">Visitor Views</h2>
                                <button onclick="refreshDashboard()" class="refresh-btn bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">Refresh</button>
                            </div>
                            {% if visitors %}
                                <div class="table-container">
                                    <table>
                                        <thead>
                                            <tr class="bg-gray-200">
                                                <th>#</th>
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
                                                    <td>{{ visitor.index }}</td>
                                                    <td>{{ visitor.timestamp }}</td>
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
                        <div class="bg-white p-8 rounded-lg card">
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
                    <div id="analytics-tab" class="tab-content hidden">
                        <div class="bg-white p-8 rounded-lg card">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">Traffic Analytics</h2>
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <h3 class="text-lg font-semibold mb-4">Traffic Sources</h3>
                                    <canvas id="traffic-source-chart"></canvas>
                                    <script>
                                        new Chart(document.getElementById('traffic-source-chart'), {
                                            type: 'pie',
                                            data: {
                                                labels: {{ traffic_sources_keys|tojson }},
                                                datasets: [{
                                                    data: {{ traffic_sources_values|tojson }},
                                                    backgroundColor: ['#4f46e5', '#7c3aed', '#3b82f6']
                                                }]
                                            },
                                            options: {
                                                responsive: true,
                                                plugins: {
                                                    legend: { position: 'top' }
                                                }
                                            }
                                        });
                                    </script>
                                </div>
                                <div>
                                    <h3 class="text-lg font-semibold mb-4">Bot vs Human Ratio</h3>
                                    <canvas id="bot-ratio-chart"></canvas>
                                    <script>
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
                                                plugins: {
                                                    legend: { position: 'top' }
                                                }
                                            }
                                        });
                                    </script>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        """, username=username, urls=urls, visitors=visitors, bot_logs=bot_logs, 
           traffic_sources_keys=traffic_sources_keys, traffic_sources_values=traffic_sources_values, 
           bot_ratio_keys=bot_ratio_keys, bot_ratio_values=bot_ratio_values, 
           primary_color=primary_color, error=error, valkey_error=valkey_error)
    except Exception as e:
        logger.error(f"Dashboard error for user {username}: {str(e)}")
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/toggle_analytics/<url_id>", methods=["POST"])
@login_required
def toggle_analytics(url_id):
    try:
        username = session['username']
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
            logger.warning("Valkey unavailable for toggle_analytics")
            return jsonify({"status": "error", "message": "Database unavailable"}), 500
    except Exception as e:
        logger.error(f"Error in toggle_analytics: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/clear_views/<url_id>", methods=["GET"])
@login_required
def clear_views(url_id):
    try:
        username = session['username']
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                abort(404, "URL not found")
            valkey_client.delete(f"{key}:visits")
            valkey_client.hset(key, "clicks", 0)
            logger.debug(f"Cleared views for URL {url_id}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning("Valkey unavailable for clear_views")
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
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                        <p class="text-gray-600">Database unavailable.</p>
                    </div>
                </body>
                </html>
            """), 500
    except Exception as e:
        logger.error(f"Error in clear_views: {str(e)}")
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

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
            valkey_client.delete(key, f"{key}:visits")
            logger.debug(f"Deleted URL {url_id}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning("Valkey unavailable for delete_url")
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
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                        <p class="text-gray-600">Database unavailable.</p>
                    </div>
                </body>
                </html>
            """), 500
    except Exception as e:
        logger.error(f"Error in delete_url: {str(e)}")
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/export_visitors", methods=["GET"])
@login_required
def export_visitors():
    try:
        username = session['username']
        logger.debug(f"Exporting visitor data for user: {username}")
        if valkey_client:
            try:
                visitor_keys = valkey_client.keys(f"user:{username}:visitor:*")
                visitor_data = []
                for key in visitor_keys:
                    try:
                        visitor = valkey_client.hgetall(key)
                        visitor_data.append(visitor)
                    except Exception as e:
                        logger.error(f"Error processing visitor key {key}: {str(e)}")
                visitor_data.sort(key=lambda x: int(x.get('timestamp', 0)), reverse=True)
                output = StringIO()
                writer = csv.writer(output)
                writer.writerow(['Index', 'Timestamp', 'IP', 'Country', 'Region', 'City', 'Lat', 'Lon', 'ISP', 'Timezone', 'Device', 'Application', 'User Agent', 'Bot Status', 'Block Reason', 'Source', 'Session Duration (s)'])
                for index, visitor in enumerate(visitor_data, 1):
                    writer.writerow([
                        index,
                        datetime.fromtimestamp(int(visitor.get('timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S') if visitor.get('timestamp') else 'Unknown',
                        visitor.get('ip', 'Unknown'),
                        visitor.get('country', 'Unknown'),
                        visitor.get('region', 'Unknown'),
                        visitor.get('city', 'Unknown'),
                        visitor.get('lat', '0.0'),
                        visitor.get('lon', '0.0'),
                        visitor.get('isp', 'Unknown'),
                        visitor.get('timezone', 'Unknown'),
                        visitor.get('device', 'Unknown'),
                        visitor.get('application', 'Unknown'),
                        visitor.get('user_agent', 'Unknown'),
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
                logger.error(f"Valkey error in export_visitors: {str(e)}")
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
                        <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                            <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                            <p class="text-gray-600">Database unavailable.</p>
                        </div>
                    </body>
                    </html>
                """), 500
        else:
            logger.warning("Valkey unavailable for export_visitors")
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
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                        <p class="text-gray-600">Database unavailable.</p>
                    </div>
                </body>
                </html>
            """), 500
    except Exception as e:
        logger.error(f"Error in export_visitors: {str(e)}")
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/export/<int:index>", methods=["GET"])
@login_required
def export(index):
    try:
        username = session['username']
        logger.debug(f"Exporting URL data for user: {username}, index: {index}")
        if valkey_client:
            try:
                url_keys = valkey_client.keys(f"user:{username}:url:*")
                if index <= 0 or index > len(url_keys):
                    logger.warning(f"Invalid export index {index} for user {username}")
                    abort(404, "URL not found")
                key = url_keys[index-1]
                url_id = key.split(':')[-1]
                visits = valkey_client.lrange(f"{key}:visits", 0, -1)
                visit_data = []
                for v in visits:
                    try:
                        visit_data.append(json.loads(v))
                    except json.JSONDecodeError as e:
                        logger.error(f"Error decoding visit data: {str(e)}")
                output = StringIO()
                writer = csv.writer(output)
                writer.writerow(['Timestamp', 'IP', 'Device', 'App', 'Type', 'Country', 'Region', 'City'])
                for visit in visit_data:
                    writer.writerow([
                        datetime.fromtimestamp(visit.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S') if visit.get('timestamp') else 'Unknown',
                        visit.get('ip', 'Unknown'),
                        visit.get('device', 'Unknown'),
                        visit.get('app', 'Unknown'),
                        visit.get('type', 'Unknown'),
                        visit.get('location', {}).get('country', 'Unknown'),
                        visit.get('location', {}).get('region', 'Unknown'),
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
                logger.error(f"Valkey error in export: {str(e)}")
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
                        <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                            <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                            <p class="text-gray-600">Database unavailable.</p>
                        </div>
                    </body>
                    </html>
                """), 500
        else:
            logger.warning("Valkey unavailable for export")
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
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                        <p class="text-gray-600">Database unavailable.</p>
                    </div>
                </body>
                </html>
            """), 500
    except Exception as e:
        logger.error(f"Error in export: {str(e)}")
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/challenge", methods=["POST"])
def challenge():
    try:
        data = request.get_json()
        if not data or 'challenge' not in data or not isinstance(data['challenge'], (int, float)):
            logger.warning("Invalid JS challenge")
            return jsonify({"status": "denied"}), 403
        session['js_verified'] = True
        session.permanent = True
        session.modified = True
        logger.debug("JS challenge passed")
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logger.error(f"Error in challenge: {str(e)}")
        return jsonify({"status": "error"}), 500

@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    try:
        data = request.get_json()
        if data and 'fingerprint' in data:
            fingerprint = generate_fingerprint()
            if valkey_client:
                try:
                    valkey_client.setex(f"fingerprint:{fingerprint}", 3600, data['fingerprint'])
                    logger.debug(f"Fingerprint stored: {fingerprint[:10]}...")
                except Exception as e:
                    logger.error(f"Valkey error storing fingerprint: {str(e)}")
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logger.error(f"Error in fingerprint: {str(e)}")
        return jsonify({"status": "error"}), 500

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
        logger.debug(f"Redirect handler: username={username}, base_domain={base_domain}, endpoint={endpoint}, "
                     f"payload={encrypted_payload[:20]}..., path_segment={path_segment}, IP={ip}, UA={user_agent}, URL={request.url}")
        logger.debug(f"ENCRYPTION_KEY hash: {hashlib.sha256(ENCRYPTION_KEY).hexdigest()[:10]}...")

        is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, request.path)
        asn_blocked = check_asn(ip)
        ua = parse(user_agent)
        device = "Desktop" if not ua.is_mobile else "Android" if "Android" in user_agent else "iPhone" if "iPhone" in user_agent else "Mobile"
        app = "Outlook" if "Outlook" in user_agent else ua.browser.family if ua.browser.family else "Unknown"
        visit_type = "Human"
        if is_bot_flag or asn_blocked:
            visit_type = "Bot" if "curl/" in user_agent.lower() else "Mimicry" if "Mimicry" in bot_reason else "Bot"
        elif app != "Unknown" and app != ua.browser.family:
            visit_type = "App"

        location = get_geoip(ip)
        session_duration = int(time.time()) - session_start
        url_id = hashlib.sha256(request.url.encode()).hexdigest()

        if valkey_client:
            try:
                analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id}", "analytics_enabled") == "1"
                if analytics_enabled:
                    fingerprint = generate_fingerprint()
                    visitor_id = hashlib.sha256(f"{ip}{fingerprint}".encode()).hexdigest()
                    if not valkey_client.exists(f"user:{username}:visitor:{visitor_id}"):
                        valkey_client.hset(f"user:{username}:visitor:{visitor_id}", mapping={
                            "timestamp": int(time.time()),
                            "ip": ip,
                            "country": location['country'],
                            "city": location['city'],
                            "region": location['region'],
                            "lat": str(location['lat']),
                            "lon": str(location['lon']),
                            "isp": location['isp'],
                            "timezone": location['timezone'],
                            "device": device,
                            "application": app,
                            "user_agent": user_agent,
                            "bot_status": visit_type,
                            "block_reason": bot_reason if is_bot_flag or asn_blocked else "N/A",
                            "referer": referer,
                            "source": 'referral' if referer else 'direct',
                            "session_duration": session_duration
                        })
                        valkey_client.expire(f"user:{username}:visitor:{visitor_id}", DATA_RETENTION_DAYS * 86400)
                    valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)
                    valkey_client.lpush(f"user:{username}:url:{url_id}:visits", json.dumps({
                        "timestamp": int(time.time()),
                        "ip": ip,
                        "device": device,
                        "app": app,
                        "type": visit_type,
                        "location": location
                    }))
                    valkey_client.expire(f"user:{username}:url:{url_id}:visits", DATA_RETENTION_DAYS * 86400)
                    logger.debug(f"Logged visit for URL ID: {url_id}")
            except Exception as e:
                logger.error(f"Valkey error logging visit: {str(e)}")

        if is_bot_flag or asn_blocked:
            logger.warning(f"Blocked redirect for IP {ip}: {bot_reason}")
            abort(403, f"Access denied: {bot_reason}")

        try:
            encrypted_payload = urllib.parse.unquote(encrypted_payload)
            logger.debug(f"Unquoted payload: {encrypted_payload[:50]}...")
        except Exception as e:
            logger.error(f"Error unquoting payload: {str(e)}")
            abort(400, "Invalid payload format")

        payload = None
        for method in ['heap_x3', 'pow', 'chacha20_poly1305', 'aes_gcm_alt', 'fern128']:
            try:
                logger.debug(f"Attempting decryption with {method}")
                if method == 'heap_x3':
                    data = decrypt_heap_x3(encrypted_payload)
                    payload = data['payload']
                    if data['fingerprint'] != generate_fingerprint():
                        logger.warning("Fingerprint mismatch in heap_x3")
                        continue
                elif method == 'pow':
                    payload = decrypt_pow(encrypted_payload)
                elif method == 'chacha20_poly1305':
                    payload = decrypt_chacha20_poly1305(encrypted_payload)
                elif method == 'aes_gcm_alt':
                    payload = decrypt_aes_gcm_alt(encrypted_payload)
                else:
                    payload = decrypt_fern128(encrypted_payload)
                logger.debug(f"Decryption successful with {method}: {payload[:50]}...")
                break
            except Exception as e:
                logger.debug(f"Decryption failed with {method}: {str(e)}")
                continue

        if not payload:
            logger.error(f"All decryption methods failed for payload: {encrypted_payload[:50]}...")
            abort(400, "Invalid payload")

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                abort(400, "Invalid redirect URL")
            if time.time() > expiry:
                logger.warning("URL expired")
                abort(410, "URL expired")
            logger.debug(f"Parsed payload: redirect_url={redirect_url}")
        except Exception as e:
            logger.error(f"Payload parsing error: {str(e)}")
            abort(400, "Invalid payload")

        final_url = f"{redirect_url.rstrip('/')}/{path_segment}"
        logger.info(f"Redirecting to {final_url}")
        return redirect(final_url, code=302)
    except Exception as e:
        logger.error(f"Error in redirect_handler: {str(e)}")
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"])
@rate_limit(limit=5, per=60)
def redirect_handler_no_subdomain(endpoint, encrypted_payload, path_segment):
    try:
        host = request.host
        username = host.split('.')[0] if '.' in host else "default"
        logger.debug(f"Fallback redirect handler: username={username}, endpoint={endpoint}, "
                     f"payload={encrypted_payload[:20]}..., path_segment={path_segment}, URL={request.url}")
        return redirect_handler(username, endpoint, encrypted_payload, path_segment)
    except Exception as e:
        logger.error(f"Error in redirect_handler_no_subdomain: {str(e)}")
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
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
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
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
    logger.warning(f"404 Not Found for path: {path}, host: {request.host}, url: {request.url}")
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
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h3 class="text-lg font-bold mb-4 text-red-600">Not Found</h3>
                <p class="text-gray-600">The requested URL was not found on the server.</p>
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
        logger.error(f"Error starting Flask app: {str(e)}")
        import sys
        sys.exit(1)
