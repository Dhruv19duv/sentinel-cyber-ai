#!/usr/bin/env python3
"""
Sentinel Cyber AI - Dataset Preparation
========================================
Download, curate, and prepare cybersecurity datasets for fine-tuning.

This script creates training data for:
  - Vulnerability detection (find the bug)
  - Secure code generation (fix the bug)
  - CVE analysis (explain the vulnerability)
  - Security best practices (how to write secure code)

Usage:
    python scripts/prepare_dataset.py
    python scripts/prepare_dataset.py --output ./data/processed/cyber_train.jsonl
    python scripts/prepare_dataset.py --samples 100 --tiny  # Quick test
"""

import os
import sys
import json
import random
import argparse
import logging
from typing import List, Dict, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
# VULNERABLE CODE EXAMPLES
# ══════════════════════════════════════════════════════════════════════

VULNERABLE_CODE_EXAMPLES = [
    # ---- SQL Injection ----
    {
        "instruction": "Analyze this code for security vulnerabilities and provide a fix.",
        "input": """def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()""",
        "output": "## Vulnerability: SQL Injection\n\n**Severity: CRITICAL**\n\nThe code directly interpolates user input into a SQL query string, allowing an attacker to manipulate the query by providing crafted input like `' OR '1'='1`.\n\n### Fix:\n```python\ndef get_user(username):\n    query = \"SELECT * FROM users WHERE username = ?\"\n    cursor.execute(query, (username,))\n    return cursor.fetchall()\n```\n\nAlways use parameterized queries or an ORM to safely handle user input in database operations.",
    },
    {
        "instruction": "Find and fix the security vulnerability in this code.",
        "input": """String query = "SELECT * FROM products WHERE id = " + request.getParameter("id");
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);""",
        "output": "## Vulnerability: SQL Injection\n\n**Severity: CRITICAL**\n\nUser input from `request.getParameter(\"id\")` is concatenated directly into a SQL query string, enabling SQL injection attacks.\n\n### Fix:\n```java\nString query = \"SELECT * FROM products WHERE id = ?\";\nPreparedStatement stmt = connection.prepareStatement(query);\nstmt.setString(1, request.getParameter(\"id\"));\nResultSet rs = stmt.executeQuery();\n```\n\nUse `PreparedStatement` with parameterized queries to prevent injection.",
    },
    # ---- XSS ----
    {
        "instruction": "Is this code vulnerable? If so, explain the vulnerability and fix it.",
        "input": """function displayMessage() {
    const name = new URLSearchParams(window.location.search).get('name');
    document.getElementById('greeting').innerHTML = 'Hello, ' + name + '!';
}""",
        "output": "## Vulnerability: Cross-Site Scripting (XSS)\n\n**Severity: HIGH**\n\nThe code inserts unsanitized URL parameter content directly into the DOM using `innerHTML`. An attacker can craft a URL with malicious JavaScript in the `name` parameter (e.g., `?name=<script>alert('xss')</script>`) to execute arbitrary scripts in the victim's browser.\n\n### Fix:\n```javascript\nfunction displayMessage() {\n    const name = new URLSearchParams(window.location.search).get('name');\n    const greeting = document.getElementById('greeting');\n    greeting.textContent = 'Hello, ' + name + '!';\n}\n```\n\nUse `textContent` instead of `innerHTML`, or properly sanitize/escape any HTML content before insertion. Consider using a Content Security Policy (CSP) header as defense-in-depth.",
    },
    {
        "instruction": "Identify security issues in this code and provide remediation.",
        "input": """<div>
  <h1>Welcome</h1>
  <p><?php echo $_GET['message']; ?></p>
</div>""",
        "output": "## Vulnerability: Cross-Site Scripting (XSS)\n\n**Severity: HIGH**\n\nUser input from the `message` query parameter is directly echoed into HTML without sanitization, allowing an attacker to inject arbitrary HTML/JavaScript.\n\n### Fix:\n```php\n<div>\n  <h1>Welcome</h1>\n  <p><?php echo htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8'); ?></p>\n</div>\n```\n\nUse `htmlspecialchars()` with `ENT_QUOTES` to encode HTML special characters and prevent script injection.",
    },
    # ---- Command Injection ----
    {
        "instruction": "Review this code for security flaws and suggest fixes.",
        "input": """import subprocess

def ping_host(hostname):
    result = subprocess.run(f"ping -c 4 {hostname}", shell=True, capture_output=True)
    return result.stdout""",
        "output": "## Vulnerability: Command Injection\n\n**Severity: CRITICAL**\n\nThe code passes user-controlled input (`hostname`) directly to a shell command using `shell=True`. An attacker can provide input like `; rm -rf /` or `$(malicious_command)` to execute arbitrary commands on the server.\n\n### Fix:\n```python\nimport subprocess\nimport shlex\n\ndef ping_host(hostname):\n    # Validate input: only allow valid hostnames/IPs\n    if not is_valid_hostname(hostname):\n        raise ValueError(\"Invalid hostname\")\n    \n    # Use a list of arguments to avoid shell injection\n    result = subprocess.run(\n        [\"ping\", \"-c\", \"4\", hostname],\n        capture_output=True,\n        timeout=30\n    )\n    return result.stdout\n\ndef is_valid_hostname(hostname):\n    import re\n    # Simple hostname/IP validation\n    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$|^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$'\n    return bool(re.match(pattern, hostname))\n```\n\nNever use `shell=True` with user input. Use argument lists and validate all inputs.",
    },
    # ---- Path Traversal ----
    {
        "instruction": "Find the security vulnerability in this file access function.",
        "input": """def read_user_file(filename):
    base_path = "/var/data/users/"
    full_path = base_path + filename
    with open(full_path, 'r') as f:
        return f.read()""",
        "output": "## Vulnerability: Path Traversal\n\n**Severity: HIGH**\n\nThe `filename` parameter is concatenated directly with the base path without sanitization. An attacker can use `../` sequences to read arbitrary files outside the intended directory (e.g., `../../etc/passwd`).\n\n### Fix:\n```python\nimport os\n\ndef read_user_file(filename):\n    base_path = \"/var/data/users/\"\n    \n    # Normalize and resolve the path\n    full_path = os.path.normpath(os.path.join(base_path, filename))\n    \n    # Ensure the resolved path is within the allowed directory\n    if not full_path.startswith(os.path.normpath(base_path)):\n        raise SecurityError(\"Path traversal detected\")\n    \n    with open(full_path, 'r') as f:\n        return f.read()\n```\n\nAlways normalize paths and validate they remain within the intended directory.",
    },
    # ---- Insecure Deserialization ----
    {
        "instruction": "Identify the security issue in this deserialization code.",
        "input": """import pickle

def load_session(session_data):
    return pickle.loads(base64.b64decode(session_data))""",
        "output": "## Vulnerability: Insecure Deserialization\n\n**Severity: CRITICAL**\n\nPython's `pickle` module can execute arbitrary code during deserialization. If an attacker can control the serialized data, they can craft a payload that executes malicious code when `pickle.loads()` is called.\n\n### Fix:\n```python\nimport json\nimport base64\n\ndef load_session(session_data):\n    # Use a safe format like JSON instead of pickle\n    return json.loads(base64.b64decode(session_data).decode('utf-8'))\n```\n\nNever deserialize untrusted data with `pickle`, `yaml.load()` (without SafeLoader), or similar unsafe deserializers. Use safe formats like JSON or a schema-validated serialization library.",
    },
    # ---- Hardcoded Secrets ----
    {
        "instruction": "What security issue do you see in this configuration file?",
        "input": """# config.py
DB_HOST = "localhost"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
API_SECRET = "sk-live-abcdefghijklmnopqrstuvwxyz"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" """,
        "output": "## Vulnerability: Hardcoded Secrets\n\n**Severity: HIGH**\n\nDatabase passwords, API keys, and AWS secret keys are hardcoded in the source code. This exposes credentials in:\n- Version control history (git)\n- CI/CD logs\n- Compiled/packaged applications\n- Any system with access to the code\n\n### Fix:\n```python\n# config.py\nimport os\nfrom dotenv import load_dotenv\n\nload_dotenv()\n\nDB_HOST = os.getenv(\"DB_HOST\", \"localhost\")\nDB_USER = os.getenv(\"DB_USER\", \"admin\")\nDB_PASSWORD = os.environ[\"DB_PASSWORD\"]  # Will raise KeyError if not set\nAPI_SECRET = os.environ[\"API_SECRET\"]\nAWS_SECRET_KEY = os.environ[\"AWS_SECRET_KEY\"]\n```\n\nUse environment variables or a secrets manager (like HashiCorp Vault, AWS Secrets Manager) for all credentials. Add a `.env.example` file with placeholder values and ensure `.env` is in `.gitignore`.",
    },
    # ---- CSRF ----
    {
        "instruction": "Analyze this form handler for security vulnerabilities.",
        "input": """@app.route('/transfer', methods=['POST'])
def transfer_money():
    to_account = request.form['to_account']
    amount = request.form['amount']
    
    # Transfer logic
    current_user.transfer(to_account, amount)
    return redirect('/success')""",
        "output": "## Vulnerability: Cross-Site Request Forgery (CSRF)\n\n**Severity: HIGH**\n\nThis endpoint performs a sensitive action (money transfer) without verifying that the request originated from the legitimate application. An attacker can create a malicious page that auto-submits a form to this endpoint, performing actions as the authenticated victim.\n\n### Fix:\n```python\nfrom flask_wtf.csrf import CSRFProtect\n\ncsrf = CSRFProtect(app)\n\n@app.route('/transfer', methods=['POST'])\ndef transfer_money():\n    to_account = request.form['to_account']\n    amount = request.form['amount']\n    \n    # Re-authenticate for sensitive actions\n    if not request.form.get('confirm_password') or not verify_password(current_user, request.form['confirm_password']):\n        return redirect('/transfer?error=reauthentication_required')\n    \n    current_user.transfer(to_account, amount)\n    return redirect('/success')\n```\n\nUse CSRF tokens on all state-changing forms. Consider requiring password confirmation for sensitive operations.",
    },
    # ---- Insecure Randomness ----
    {
        "instruction": "Find the cryptographic weakness in this code.",
        "input": """import random

def generate_reset_token():
    """Generate a password reset token."""
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    token = ''.join(random.choice(chars) for _ in range(20))
    return token""",
        "output": "## Vulnerability: Insecure Randomness\n\n**Severity: MEDIUM**\n\nThe `random` module uses the Mersenne Twister PRNG, which is predictable. If an attacker can obtain one token, they can predict future tokens (and possibly past ones) because the PRNG state can be reconstructed from observed outputs.\n\n### Fix:\n```python\nimport secrets\n\ndef generate_reset_token():\n    \"\"\"Generate a cryptographically secure password reset token.\"\"\"\n    return secrets.token_urlsafe(32)\n```\n\nUse `secrets` module (Python 3.6+) or `os.urandom()` for any security-related randomness: tokens, keys, nonces, or passwords.",
    },
    # ---- SSRF ----
    {
        "instruction": "What security issue exists in this URL fetching code?",
        "input": """def fetch_url(url):
    response = requests.get(url)
    return response.text""",
        "output": "## Vulnerability: Server-Side Request Forgery (SSRF)\n\n**Severity: HIGH**\n\nIf `url` is user-controlled, an attacker can make the server send requests to internal services (e.g., `http://169.254.169.254/latest/meta-data/` for cloud metadata, `http://localhost:6379` for Redis, or internal APIs).\n\n### Fix:\n```python\nfrom urllib.parse import urlparse\n\ndef is_safe_url(url):\n    parsed = urlparse(url)\n    \n    # Block internal IPs and hostnames\n    blocked_hosts = [\n        'localhost', '127.0.0.1', '0.0.0.0',\n        '169.254.169.254',  # Cloud metadata\n        'metadata.google.internal',\n    ]\n    \n    if parsed.hostname in blocked_hosts:\n        return False\n    \n    # Block private IP ranges\n    import ipaddress\n    try:\n        ip = ipaddress.ip_address(parsed.hostname)\n        if ip.is_private or ip.is_loopback:\n            return False\n    except ValueError:\n        pass  # Not an IP, continue\n    \n    return True\n\ndef fetch_url(url):\n    if not is_safe_url(url):\n        raise ValueError(\"URL is not allowed\")\n    \n    response = requests.get(url, timeout=10)\n    return response.text\n```\n\nAlways validate and restrict URLs to prevent SSRF attacks. Use an allowlist approach when possible.",
    },
    # ---- Race Condition ----
    {
        "instruction": "Identify the concurrency vulnerability in this code.",
        "input": """import os

def process_transaction(account_id, amount):
    balance_file = f\"/var/accounts/{account_id}.txt\"
    
    # Read current balance
    with open(balance_file, 'r') as f:\n        balance = int(f.read().strip())\n    \n    # Check sufficient funds\n    if balance >= amount:\n        # Simulate processing delay\n        import time\n        time.sleep(0.1)\n        \n        # Write new balance\n        with open(balance_file, 'w') as f:\n            f.write(str(balance - amount))\n        return True\n    return False""",
        "output": "## Vulnerability: Race Condition (TOCTOU)\n\n**Severity: HIGH**\n\nThis code suffers from a Time-of-Check to Time-of-Use (TOCTOU) race condition. Between reading the balance and writing the new balance, another concurrent request can also read the balance. Both requests see sufficient funds, and both succeed — allowing an attacker to drain more money than they have.\n\n### Fix:\n```python\nimport fcntl\nimport os\n\ndef process_transaction(account_id, amount):\n    balance_file = f\"/var/accounts/{account_id}.txt\"\n    \n    with open(balance_file, 'r+') as f:\n        # Acquire an exclusive file lock\n        fcntl.flock(f.fileno(), fcntl.LOCK_EX)\n        \n        # Read and update balance atomically\n        balance = int(f.read().strip())\n        if balance < amount:\n            return False\n        \n        f.seek(0)\n        f.write(str(balance - amount))\n        f.truncate()\n        \n        # Release the lock\n        fcntl.flock(f.fileno(), fcntl.LOCK_UN)\n    \n    return True\n```\n\nUse database transactions (ACID), file locks, or atomic operations to prevent race conditions on shared resources.",
    },
    # ---- LDAP Injection ----
    {
        "instruction": "Identify the injection vulnerability in this LDAP query.",
        "input": """def authenticate_user(username, password):
    ldap_filter = f\"(&(uid={username})(userPassword={password}))\"
    results = ldap_connection.search(search_filter=ldap_filter)
    return len(results) > 0""",
        "output": "## Vulnerability: LDAP Injection\n\n**Severity: HIGH**\n\nUser input is directly interpolated into an LDAP filter string. An attacker can inject LDAP metacharacters to manipulate the query. For example, username `*` matches all users, while `admin)(&)` can bypass authentication.\n\n### Fix:\n```python\nimport ldap3\nfrom ldap3.utils.conv import escape_filter_chars\n\ndef authenticate_user(username, password):\n    # Escape LDAP special characters\n    safe_username = escape_filter_chars(username)\n    safe_password = escape_filter_chars(password)\n    \n    ldap_filter = f\"(&(uid={safe_username})(userPassword={safe_password}))\"\n    results = ldap_connection.search(search_filter=ldap_filter)\n    return len(results) > 0\n```\n\nAlways escape special characters when building LDAP filters with user input, or use parameterized LDAP queries.",
    },
    # ---- NoSQL Injection ----
    {
        "instruction": "Find the vulnerability in this MongoDB query.",
        "input": """db.users.find({
    "username": request.json["username"],
    "password": request.json["password"]
})""",
        "output": "## Vulnerability: NoSQL Injection\n\n**Severity: HIGH**\n\nMongoDB accepts operators like `$ne` (not equal), `$gt` (greater than), `$regex`, etc. An attacker can send a JSON object like `{\"$ne\": \"\"}` as the password, which matches any non-empty password — bypassing authentication entirely.\n\n### Fix:\n```python\n# Validate that inputs are strings, not objects\nusername = request.json.get(\"username\")\npassword = request.json.get(\"password\")\n\nif not isinstance(username, str) or not isinstance(password, str):\n    return {\"error\": \"Invalid input format\"}, 400\n\nuser = db.users.find_one({\n    \"username\": username,\n    \"password\": hash_password(password)  # Always hash passwords!\n})\n```\n\nValidate that user inputs are plain strings (not objects), hash passwords, and use an ODM like MongoEngine that provides type validation.",
    },
    # ---- Open Redirect ----
    {
        "instruction": "What security issue exists in this redirect function?",
        "input": """@app.route('/redirect')
def redirect_page():
    url = request.args.get('next', '/')
    return redirect(url)""",
        "output": "## Vulnerability: Open Redirect\n\n**Severity: MEDIUM**\n\nAn attacker can redirect users to arbitrary external websites by passing a crafted URL (e.g., `/redirect?next=https://evil-phishing-site.com`). This can be used in phishing attacks.\n\n### Fix:\n```python\nfrom urllib.parse import urlparse, urljoin\n\n@app.route('/redirect')\ndef redirect_page():\n    url = request.args.get('next', '/')\n    \n    # Only allow relative paths or same-origin URLs\n    parsed = urlparse(url)\n    if parsed.netloc and parsed.netloc != request.host:\n        url = '/'\n    \n    return redirect(url)\n```\n\nValidate that redirect targets are either relative URLs or belong to the same origin. Use an allowlist of permitted domains if external redirects are needed.",
    },
    # ---- XXE ----
    {
        "instruction": "Identify the XML-related vulnerability in this code.",
        "input": """from xml.etree.ElementTree import parse

def process_xml_upload(filepath):
    tree = parse(filepath)
    root = tree.getroot()
    return root.find('data').text""",
        "output": "## Vulnerability: XML External Entity (XXE) Injection\n\n**Severity: HIGH**\n\nThe default XML parser processes external entities. An attacker can craft an XML file that reads local files, performs SSRF, or causes denial of service (Billion Laughs attack).\n\nExample malicious XML:\n```xml\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<root><data>&xxe;</data></root>\n```\n\n### Fix:\n```python\nfrom xml.etree.ElementTree import parse, XMLParser\n\ndef process_xml_upload(filepath):\n    # Disable external entity resolution\n    parser = XMLParser()\n    parser.parser.UseForeignDTD(False)\n    \n    tree = parse(filepath, parser=parser)\n    root = tree.getroot()\n    return root.find('data').text\n```\n\nBetter yet, use `defusedxml` library which provides safe XML parsers:\n```python\nfrom defusedxml.ElementTree import parse\n\ndef process_xml_upload(filepath):\n    tree = parse(filepath)\n    root = tree.getroot()\n    return root.find('data').text\n```",
    },
]


# ══════════════════════════════════════════════════════════════════════
# CWE/CVE DESCRIPTIONS (Abridged)
# ══════════════════════════════════════════════════════════════════════

CWE_EXAMPLES = [
    {
        "instruction": "Explain this CWE category and how to prevent it.",
        "input": "CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
        "output": "## CWE-79: Cross-Site Scripting (XSS)\n\n**Description:** The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page.\n\n**Impact:** An attacker can execute arbitrary JavaScript in a victim's browser, leading to session theft, credential harvesting, defacement, or malware delivery.\n\n**Variants:**\n- **Reflected XSS:** Malicious script comes from the current HTTP request\n- **Stored XSS:** Script is stored on the server (e.g., in a database)\n- **DOM-based XSS:** Vulnerability exists in client-side JavaScript rather than server-side\n\n**Prevention:**\n1. Use context-aware output encoding (HTML entity, JavaScript, CSS, URL encoding)\n2. Implement Content Security Policy (CSP) headers\n3. Use frameworks that auto-escape (React, Angular, Vue)\n4. Validate and sanitize input on both client and server sides\n5. Use `textContent` instead of `innerHTML` when possible",
    },
    {
        "instruction": "Explain this CWE category and how to prevent it.",
        "input": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "output": "## CWE-89: SQL Injection\n\n**Description:** The product constructs all or part of an SQL command using externally-influenced input without properly neutralizing special elements.\n\n**Impact:** Attackers can read, modify, or delete database contents; execute administrative operations; or in some cases execute commands on the database server.\n\n**Prevention:**\n1. Use parameterized queries / prepared statements (strongest defense)\n2. Use ORM frameworks with safe query builders\n3. Implement least privilege database accounts\n4. Validate and sanitize all inputs\n5. Use stored procedures with parameterized calls\n6. Escape special characters only as a secondary defense\n\n**Example vulnerable code:**\n```python\n# Vulnerable\nquery = f\"SELECT * FROM users WHERE username = '{user_input}'\"\n\n# Safe\nquery = \"SELECT * FROM users WHERE username = ?\"\ncursor.execute(query, (user_input,))\n```",
    },
    {
        "instruction": "Explain this CWE and its secure coding practices.",
        "input": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "output": "## CWE-22: Path Traversal\n\n**Description:** The product uses external input to construct a pathname that is intended to identify a file or directory underneath a restricted parent directory, but the product does not properly neutralize special elements that can cause the pathname to resolve to a location outside the restricted directory.\n\n**Impact:** Attackers can read arbitrary files on the server (configuration files, source code, /etc/passwd, etc.). In some cases, they may be able to write files or execute code.\n\n**Prevention:**\n1. Use an allowlist of permitted filenames\n2. Canonicalize the path and verify it starts with the expected base directory\n3. Use a chroot jail or container to limit file system access\n4. Avoid sending raw file paths to the file system API\n\n**Example:**\n```python\nimport os\n\ndef safe_read(base_dir, filename):\n    # Resolve the full path\n    full_path = os.path.realpath(os.path.join(base_dir, filename))\n    \n    # Verify it's within the base directory\n    if not full_path.startswith(os.path.realpath(base_dir)):\n        raise PermissionError(\"Access denied\")\n    \n    with open(full_path, 'r') as f:\n        return f.read()\n```",
    },
]


# ══════════════════════════════════════════════════════════════════════
# SECURE CODE REVIEW (Code snippets needing review)
# ══════════════════════════════════════════════════════════════════════

SECURE_CODING_EXAMPLES = [
    {
        "instruction": "How should passwords be stored securely? Show the correct implementation.",
        "input": "I need to store user passwords in my database.",
        "output": "## Secure Password Storage\n\n**Never store passwords in plaintext!**\n\n### Correct approach (Python):\n```python\nimport hashlib\n# NO! Don't use plain SHA/MD5 — they're too fast and rainbow tables exist\n\n# YES: Use a dedicated password hashing library\nimport bcrypt\n\ndef hash_password(password: str) -> str:\n    \"\"\"Hash a password with a salt using bcrypt.\"\"\"\n    salt = bcrypt.gensalt(rounds=12)  # 2^12 iterations\n    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)\n    return hashed.decode('utf-8')\n\ndef verify_password(password: str, hashed: str) -> bool:\n    \"\"\"Verify a password against its hash.\"\"\"\n    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))\n```\n\n### Key principles:\n1. **Use a slow hash function**: bcrypt, scrypt, argon2, or PBKDF2\n2. **Always use a unique salt** per password\n3. **Use a high work factor** (cost/time)\n4. **Never roll your own cryptography**\n5. **Use established libraries** — they handle edge cases correctly\n\nFor Python, `bcrypt` or `passlib` are recommended. For Node.js, use `bcrypt`. For Java, use `BCrypt` from jBCrypt.",
    },
    {
        "instruction": "How do I set up HTTPS properly for my web application?",
        "input": "I want to secure my web application with HTTPS.",
        "output": "## Securing a Web Application with HTTPS\n\n### 1. Obtain an SSL/TLS Certificate\n- Use **Let's Encrypt** (free, automated via Certbot)\n- Or purchase from a trusted CA (DigiCert, Sectigo, etc.)\n\n### 2. Configure the Web Server\n```nginx\n# Nginx example\nserver {\n    listen 443 ssl http2;\n    server_name example.com;\n\n    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n\n    # Modern TLS configuration\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n    ssl_prefer_server_ciphers off;\n\n    # HSTS (HTTP Strict Transport Security)\n    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";\n\n    # Other security headers\n    add_header X-Content-Type-Options nosniff;\n    add_header X-Frame-Options DENY;\n    add_header X-XSS-Protection \"0\";  # Deprecated, use CSP instead\n    add_header Content-Security-Policy \"default-src 'self'\";\n\n    root /var/www/html;\n}\n\n# Redirect HTTP to HTTPS\nserver {\n    listen 80;\n    server_name example.com;\n    return 301 https://$server_name$request_uri;\n}\n```\n\n### 3. Test Your Configuration\n```bash\ncurl https://example.com -vI\n# Or use: https://www.ssllabs.com/ssltest/\n```",
    },
]


def create_dataset(
    output_path: str,
    num_samples: int = -1,
    seed: int = 42,
) -> List[Dict[str, str]]:
    """Create a combined cybersecurity dataset."""
    random.seed(seed)

    # Combine all examples
    all_examples = (
        VULNERABLE_CODE_EXAMPLES
        + CWE_EXAMPLES
        + SECURE_CODING_EXAMPLES
    )

    if num_samples > 0:
        all_examples = all_examples[:num_samples]

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Write to JSONL
    with open(output_path, "w", encoding="utf-8") as f:
        for example in all_examples:
            f.write(json.dumps(example, ensure_ascii=False) + "\n")

    logger.info(f"✅ Created dataset with {len(all_examples)} examples")
    logger.info(f"   Output: {output_path}")

    return all_examples


def create_train_val_split(
    input_path: str,
    output_dir: str,
    train_ratio: float = 0.9,
    seed: int = 42,
):
    """Split dataset into training and validation sets."""
    random.seed(seed)

    with open(input_path, "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f if line.strip()]

    random.shuffle(data)
    split_idx = int(len(data) * train_ratio)

    train_data = data[:split_idx]
    val_data = data[split_idx:]

    train_path = os.path.join(output_dir, "cyber_train.jsonl")
    val_path = os.path.join(output_dir, "cyber_val.jsonl")

    for path, dataset in [(train_path, train_data), (val_path, val_data)]:
        with open(path, "w", encoding="utf-8") as f:
            for example in dataset:
                f.write(json.dumps(example, ensure_ascii=False) + "\n")

    logger.info(f"✅ Train: {len(train_data)} examples -> {train_path}")
    logger.info(f"✅ Val:   {len(val_data)} examples -> {val_path}")

    return train_path, val_path


def main():
    parser = argparse.ArgumentParser(
        description="Prepare cybersecurity dataset for Sentinel Cyber AI"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./data/processed/cyber_train.jsonl",
        help="Output path for the dataset",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=-1,
        help="Number of samples to generate (-1 for all)",
    )
    parser.add_argument(
        "--tiny",
        action="store_true",
        help="Create a tiny dataset for testing (10 samples)",
    )
    parser.add_argument(
        "--split",
        action="store_true",
        help="Create train/validation split",
    )
    args = parser.parse_args()

    if args.tiny:
        args.samples = 10

    # Create the dataset
    create_dataset(args.output, num_samples=args.samples)

    # Split into train/val if requested
    if args.split:
        output_dir = os.path.dirname(args.output) or "."
        create_train_val_split(args.output, output_dir)

    logger.info("✨ Dataset preparation complete!")


if __name__ == "__main__":
    main()
