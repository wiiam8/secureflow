"""Intentionally vulnerable demo application used to exercise SecureFlow.

Every weakness below is deliberate, so the scanners have something to find.
DO NOT reuse any of this code. The "secrets" are fake and protect nothing.
"""
import hashlib
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "SuperSecret123!"  # hardcoded password (fake)
DEMO_API_KEY = "7c9e2f41ab8d03e65f1a9b4c7d2e8f30"  # hardcoded API key (fake)


@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("demo.db")
    cur = conn.execute("SELECT * FROM users WHERE name = '%s'" % name)  # SQL injection
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # command injection


@app.route("/load", methods=["POST"])
def load():
    return str(yaml.load(request.data, Loader=yaml.Loader))  # unsafe deserialization


@app.route("/hash", methods=["POST"])
def digest():
    return hashlib.md5(request.data).hexdigest()  # weak hash


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # debug server bound to all interfaces
