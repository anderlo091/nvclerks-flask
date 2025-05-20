from flask import Flask, request, redirect, render_template_string, abort, url_for
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import re
import urllib.parse
import secrets
import logging

app = Flask(__name__)
app.config['SERVER_NAME'] = 'nvclerks.com'  # Required for subdomain routing

# Configuration
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", secrets.token_bytes(32))  # 256-bit key, set in Vercel environment
BASE_DOMAIN = "nvclerks.com"

# Logging setup for debugging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Bot detection patterns
BOT_PATTERNS = [
    "bot", "crawl", "spider", "slurp", "curl", "wget", "python", "scrapy",
    "facebookexternalhit", "googlebot", "bingbot", "yandex", "duckduckbot"
]

def is_bot(user_agent):
    if not user_agent:
        return False
    user_agent = user_agent.lower()
    return any(pattern in user_agent for pattern in BOT_PATTERNS)

def generate_random_string(length):
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(characters) for _ in range(length))

def generate_random_word():
    words = ["alpha", "beta", "gamma", "delta", "omega", "zeta", "theta", "sigma", "phi", "pi", "lambda", "mu", "nu", "xi", "rho"]
    random_word = secrets.choice(words)
    random_string = generate_random_string(6)
    return random_word + random_string

def encrypt_payload(payload):
    try:
        iv = secrets.token_bytes(12)  # 96-bit IV for AES-GCM
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data = payload.encode("utf-8")
        ciphertext = encryptor.update(data) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag
        return base64.b64encode(encrypted).decode("utf-8")
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_payload(encrypted_payload):
    try:
        encrypted = base64.b64decode(encrypted_payload)
        iv = encrypted[:12]
        tag = encrypted[-16:]
        ciphertext = encrypted[12:-16]
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted.decode("utf-8")
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

@app.route("/", methods=["GET"])
def index():
    user_agent = request.headers.get("User-Agent", "")
    logger.debug(f"Index accessed, User-Agent: {user_agent}")
    if is_bot(user_agent):
        logger.warning("Bot detected")
        abort(403, "Blocked - Bot detected")
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head><meta charset="UTF-8"><title>Student URL Generator</title></head>
        <body>
            <h1>Generate Student URL</h1>
            <form method="POST" action="{{ url_for('generate') }}">
                <label>Student Name: <input type="text" name="student_name" required></label><br>
                <label>Student Link: <input type="url" name="student_link" required></label><br>
                <button>Generate URL</button>
            </form>
        </body>
        </html>
    """)

@app.route("/generate", methods=["POST"])
def generate():
    user_agent = request.headers.get("User-Agent", "")
    logger.debug(f"Generate accessed, User-Agent: {user_agent}")
    if is_bot(user_agent):
        logger.warning("Bot detected")
        abort(403, "Blocked - Bot detected")

    student_name = request.form.get("student_name", "default")
    student_link = request.form.get("student_link", "https://example.com")
    
    # Validate student_link
    if not re.match(r"^https?://", student_link):
        logger.error(f"Invalid URL: {student_link}")
        abort(400, "Invalid URL: Must start with http:// or https://")

    # Sanitize student name for subdomain
    sanitized_name = re.sub(r"[^a-z0-9]", "", student_name.lower())
    if not sanitized_name:
        sanitized_name = "default"

    line_id = generate_random_string(12)
    random_heap_name = generate_random_word()

    # Create payload with student_link as redirect_url
    payload = json.dumps({
        "student_link": student_link,
        "timestamp": int(os.times().elapsed * 1000),
        "random": secrets.token_hex(16),
        "redirect_url": student_link
    })

    try:
        encrypted_payload = encrypt_payload(payload)
        encoded_payload = urllib.parse.quote(encrypted_payload)
        generated_url = f"https://{sanitized_name}.{BASE_DOMAIN}/line?line_id={line_id}&{random_heap_name}={encoded_payload}"
        logger.info(f"Generated URL: {generated_url}")
    except Exception as e:
        logger.error(f"URL generation failed: {str(e)}")
        abort(500, f"Failed to generate URL: {str(e)}")

    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head><meta charset="UTF-8"><title>Generated URL</title></head>
        <body>
            <h3>Generated URL:</h3>
            <p>URL: <a href="{{ url }}" target="_blank">{{ url }}</a></p>
            <p><strong>Click the link above to be redirected to your provided destination.</strong></p>
        </body>
        </html>
    """, url=generated_url)

@app.route("/line", methods=["GET"], subdomain="<username>")
def line_redirect(username):
    user_agent = request.headers.get("User-Agent", "")
    logger.debug(f"Redirect accessed for {username}.{BASE_DOMAIN}, User-Agent: {user_agent}")
    if is_bot(user_agent):
        logger.warning("Bot detected")
        abort(403, "Blocked - Bot detected")

    line_id = request.args.get("line_id")
    params = {k: v for k, v in request.args.items() if k != "line_id"}
    if not line_id or len(params) != 1:
        logger.error("Invalid URL parameters")
        abort(400, "Invalid URL parameters")
    
    heap_param, encrypted_payload = next(iter(params.items()))
    encrypted_payload = urllib.parse.unquote(encrypted_payload)

    try:
        payload = decrypt_payload(encrypted_payload)
        data = json.loads(payload)
        redirect_url = data.get("redirect_url")
        if not redirect_url or not re.match(r"^https?://", redirect_url):
            logger.error(f"Invalid redirect URL: {redirect_url}")
            abort(400, "Invalid redirect URL")
        logger.info(f"Redirecting to {redirect_url}")
        return redirect(redirect_url, code=302)
    except Exception as e:
        logger.error(f"Redirect failed: {str(e)}")
        abort(400, f"Invalid payload or decryption error: {str(e)}")

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(500)
def handle_error(error):
    logger.error(f"Error {error.code}: {str(error)}")
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head><meta charset="UTF-8"><title>Error</title></head>
        <body>
            <h3>Error</h3>
            <p>{{ message }}</p>
        </body>
        </html>
    """, message=str(error)), error.code

if __name__ == "__main__":
    app.run(debug=False)