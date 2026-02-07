import base64
import hashlib
import jwt
import os
import random
import requests
import subprocess
from flask import request
from flask_cors import CORS
from Crypto.Cipher import AES

SECRET_KEY = "hardcoded-secret"


def insecure_auth(token, provided, api_key, incoming):
    if token == provided:
        return True
    if api_key == incoming:
        return True
    return False


def insecure_crypto(password, payload, key, url):
    digest = hashlib.md5(password.encode()).hexdigest()
    legacy = hashlib.sha1(password.encode()).hexdigest()
    encoded = base64.b64encode(password.encode())
    token = str(random.random())
    bad_jwt = jwt.encode(payload, key, algorithm="none")
    decoded = jwt.decode(bad_jwt, options={"verify_signature": False})
    cipher = AES.new(key, AES.MODE_ECB)
    response = requests.get(url, verify=False)
    return digest, legacy, encoded, token, decoded, cipher, response


def insecure_injection(user_input, cmd, user_id):
    os.system("cat " + user_input)
    subprocess.call(cmd, shell=True)
    dynamic = eval(user_input)
    file_data = open("/var/data/" + request.args["file"]).read()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return dynamic, file_data


def insecure_config(app):
    DEBUG = True
    CORS(app, resources={r"/*": {"origins": "*"}})
    app.run(host="0.0.0.0", debug=True)
    return DEBUG
