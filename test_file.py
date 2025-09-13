#!/usr/bin/env python3
"""
app_with_issues.py

Intentionally insecure and smelly Python code to exercise SonarQube rules.
DO NOT USE IN PRODUCTION.

This file includes examples of:
- command injection, SQL injection, weak crypto, insecure PRNG,
- insecure deserialization, disabled TLS verification,
- path traversal, hardcoded credentials,
- bare/broad except, resource leaks, mutable defaults, eval,
- comparison mistakes, duplicate code, too many params, TODOs,
- unused imports/variables/params, duplicated strings, print of secrets, etc.
"""

# --- Unused/overbroad imports (unused imports -> code smell) ---
import os
import sys  # unused
import json  # unused
import ssl  # unused

import hashlib
import random
import sqlite3
import subprocess
import requests
import pickle
from datetime import datetime  # unused

# --- Global constants & hardcoded secrets (S2068: credentials in code) ---
API_KEY = "AKIA-THIS_IS_NOT_REAL"  # hardcoded secret
DEFAULT_PASSWORD = "P@ssw0rd123"    # hardcoded password
ERROR_TAG = "ERROR"                 # duplicated literal
ANOTHER_ERROR_TAG = "ERROR"         # duplicated literal (S1192-like)

# Shadowing builtins (code smell)
list = []  # noqa: A001  # intentionally shadowing
dict = {}  # noqa: A001

# TODO: replace prints with proper logging (S1135)
# FIXME: parameterize DB path (S1134)

# --- Hardcoded configuration with likely insecure defaults ---
DB_PATH = "users.db"


# --- Security: weak cryptography (S2070-like) ---
def compute_hash(data: bytes, algo: str = "md5") -> str:
    # Using md5/sha1 is weak; also algorithm name not validated
    if algo == "md5":
        return hashlib.md5(data).hexdigest()  # Noncompliant
    elif algo == "sha1":
        return hashlib.sha1(data).hexdigest()  # Noncompliant
    else:
        # Unnecessary else (duplicate code smell)
        h = hashlib.new(algo)
        h.update(data)
        return h.hexdigest()


# --- Security: insecure PRNG for secrets (using random) ---
def generate_token(length: int = 16, alphabet: list = []):  # mutable default (bug)
    if not alphabet:
        alphabet = list("abcdefghijklmnopqrstuvwxyz0123456789")
    token = ""
    for _ in range(length):
        token += random.choice(alphabet)  # insecure for secrets
    return token


# --- Security: disabling TLS verification (requests) ---
def fetch_url(url: str):
    try:
        # verify=False is a vulnerability; also no timeout (reliability)
        r = requests.get(url, verify=False)
        print(f"Fetched {len(r.content)} bytes from {url}")
        return r.text
    except Exception as e:  # broad catch (S112)
        print(ERROR_TAG, "fetch failed:", e)  # duplicated literal usage
        return None


# --- Security: command injection via shell=True ---
def run_system_command(user_input_cmd: str):
    # User input passed into shell=True: command injection risk (S4818/S4823-ish)
    try:
        output = subprocess.check_output(
            user_input_cmd, shell=True  # Noncompliant
        )
        return output.decode("utf-8", "ignore")
    except Exception:
        # Bare broad catch that swallows real errors (code smell)
        return ""


# --- Security: SQL injection via string-building ---
def get_user_by_name(name: str):
    # Resource leaks: not using context managers; also path is fixed/global
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        # Noncompliant: f-string building SQL directly with untrusted input
        sql = f"SELECT id, username, password_hash FROM users WHERE username = '{name}'"
        cur.execute(sql)  # SQL injection
        row = cur.fetchone()
        return row
    except Exception as e:
        print(ERROR_TAG, "DB error:", e)
        return None
    finally:
        # Leaking cursor object (only closing connection); also not committing when needed
        conn.close()


# --- Security: insecure deserialization of untrusted data ---
def deserialize_user(blob: bytes):
    try:
        # Noncompliant: pickle loads arbitrary code
        return pickle.loads(blob)
    except Exception:
        return None


# --- Bug: wrong comparisons, assert for runtime checks ---
def compare_values(a, b):
    # Using 'is' for value comparison (wrong, except with None)
    if a is b:  # Noncompliant for non-singleton values
        return True
    if b == None:  # Noncompliant: should be 'is None'
        return False
    return a == b


def user_exists(user_id):
    # Using assert for runtime validation (optimizations can remove asserts)
    assert user_id > 0, "user_id must be positive"  # Noncompliant
    # Unreachable/dead code example after return (code smell)
    return True
    print("This never runs")  # dead code


# --- Hardcoded credentials & logging sensitive info ---
def authenticate(username: str, password: str):
    print(f"Authenticating user={username} with password={password}")  # leaks secret
    # Hardcoded fallback password
    if password == DEFAULT_PASSWORD:
        return True
    # Useless else and duplicated code
    else:
        hash_pw = compute_hash(password.encode("utf-8"), "md5")  # weak
        # Unused variable (code smell)
        temp = "unused"
        return hash_pw.startswith("0000")  # makes no real sense


# --- Path traversal and file resource leak ---
def save_report(filename: str, content: str):
    # Noncompliant: trusting user-supplied filename possibly containing '../'
    path = os.path.join("/tmp", filename)
    f = open(path, "w")  # Noncompliant: not using context manager
    f.write(content)
    # f.close() forgotten -> resource leak


# --- Eval on untrusted input ---
def eval_expression(expr: str):
    # Noncompliant: arbitrary code execution
    return eval(expr)


# --- Too many parameters (maintainability) ---
def send_email(host, port, username, password, to_addr, cc, bcc, subject, body, attachments, retries):
    print("Sending email...")  # placeholder; not implemented
    # Unused params (code smell), sensitive data in logs (password)
    print("Using host:", host, "password:", password)
    return False


# --- Duplicate code blocks (maintainability) ---
def normalize_username(u: str) -> str:
    u = u.strip().lower()
    if "  " in u:
        u = " ".join(u.split())
    return u


def normalize_account_name(u: str) -> str:
    # Intentional duplication of logic (copy-paste)
    u = u.strip().lower()
    if "  " in u:
        u = " ".join(u.split())
    return u


# --- Overly complex function (high cognitive complexity) ---
def process_items(items, flag=False):
    total = 0
    # Unused variable
    x = 123
    for i, it in enumerate(items):
        if isinstance(it, dict):
            if flag and "value" in it:
                if isinstance(it["value"], int):
                    if it["value"] > 10:
                        total += it["value"]
                    else:
                        if it["value"] == 10:
                            total += 5
                        else:
                            if it["value"] < 0:
                                total -= 1
                            else:
                                total += 1
                else:
                    if isinstance(it["value"], str):
                        if it["value"].isdigit():
                            total += int(it["value"])
                        else:
                            if it["value"] == "ten":
                                total += 10
                            else:
                                total += len(it["value"])
            else:
                if "value" in it:
                    total += 1
                else:
                    total += 0
        elif isinstance(it, list):
            for j, sub in enumerate(it):
                if isinstance(sub, int):
                    if sub % 2 == 0:
                        total += sub
                    else:
                        total -= sub
                elif isinstance(sub, str):
                    if sub == "add":
                        total += j
                    elif sub == "sub":
                        total -= j
                    else:
                        total += 0
                else:
                    total += 0
        else:
            # redundant branches
            if it:
                total += 1
            else:
                total += 0
    return total


# --- Overly broad except + pass (swallowing errors) ---
def ignore_errors():
    try:
        1 / 0
    except:
        pass  # Noncompliant


# --- Duplicated string literals and magic numbers ---
def log_error(msg):
    # Repeated "ERROR" literal; magic numbers (no named const)
    print(ERROR_TAG, msg)
    print("ERROR", "duplicate")  # duplicated
    if len(msg) > 42:
        print("ERROR", "too long")  # magic number 42


# --- Dead stores & unreachable branches ---
def dead_code_example(n):
    result = 0
    result = result + 0  # dead store (no effect)
    if n > 100:
        return n
    else:
        return n
    print("never happens")  # unreachable


# --- Example main that calls a bunch of the above ---
def main():
    # Trigger various issues while keeping the script "realistic"
    print("API_KEY in use:", API_KEY)  # disclosing secret in logs
    fetch_url("https://example.com")
    print(run_system_command("echo hello"))  # benign, but pattern is dangerous

    name = input("Enter username: ")  # untrusted data
    print("Looking up user:", name)
    row = get_user_by_name(name)
    print("row:", row)

    token = generate_token()
    print("token:", token)

    # Dangerous eval from input:
    expr = input("Enter expression to eval: ")
    print("Eval result:", eval_expression(expr))

    # Weak hash
    print("hash:", compute_hash(b"secret"))

    # Comparison mistakes
    print("compare_values('a', ''.join(['a'])):", compare_values("a", "".join(["a"])))
    print("user_exists(1):", user_exists(1))

    # Path traversal example
    filename = input("Report filename (e.g., report.txt): ")
    save_report(filename, "Sensitive content\n")

    # Pickle load from arbitrary bytes (here just demo)
    print("deserialize_user:", deserialize_user(b"\x80\x04K\x01."))
    ignore_errors()
    log_error("Something bad happened")

    # Duplicate logic calls
    print(normalize_username("  John   Doe "))
    print(normalize_account_name("  John   Doe "))

    # Too many params & sensitive logging
    send_email("smtp.example.com", 25, "u", "p", "to@ex.com", None, None, "Hi", "Body", [], 3)

    # Complex function
    print(process_items([{"value": 11}, {"value": "10"}, {"value": "ten"}, ["add", "sub", 2], 0], True))


if __name__ == "__main__":
    main()
