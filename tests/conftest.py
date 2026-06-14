"""Shared test fixtures and configuration."""

import sys
import os
import pytest
from typing import Dict, Any

# Ensure the project root is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Sample queries for testing ──

SQL_INJECTION_CODE = """def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()"""

XSS_CODE = """function displayMessage() {
    const name = new URLSearchParams(window.location.search).get('name');
    document.getElementById('output').innerHTML = name;
}"""

COMMAND_INJECTION_CODE = """import subprocess
def ping(host):
    return subprocess.run(f'ping {host}', shell=True)"""

SAFE_CODE = """def greet(name):
    return f"Hello, {name}!"
    
def add(a, b):
    return a + b"""

MULTI_VULN_CODE = """import subprocess
import sqlite3

def process_user(user_input):
    # Command injection
    subprocess.run(f"echo {user_input}", shell=True)
    
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
    
    return cursor.fetchall()"""


# ── Fixtures ──

@pytest.fixture
def sample_queries() -> Dict[str, str]:
    """Sample queries for testing different vulnerability types."""
    return {
        "sql_injection": SQL_INJECTION_CODE,
        "xss": XSS_CODE,
        "command_injection": COMMAND_INJECTION_CODE,
        "safe": SAFE_CODE,
        "multi_vuln": MULTI_VULN_CODE,
    }


@pytest.fixture
def cve_query() -> str:
    """Query containing CVE references."""
    return "Check if CVE-2021-44228 and CVE-2024-3094 affect this system"


@pytest.fixture
def exploit_query() -> str:
    """Query about exploit analysis."""
    return """Analyze this exploit chain:
    SSRF to internal metadata service to steal credentials,
    then use those credentials to pivot to internal API"""


@pytest.fixture
def patch_query() -> str:
    """Query requesting a security patch."""
    return """Fix this vulnerable code:
    def login(username, password):
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        return cursor.fetchone()"""
