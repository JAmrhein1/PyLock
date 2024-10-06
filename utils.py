# utils.py

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def resource_path(relative_path):
    """ Get absolute path to resource, works for development and deployment """
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_data_path(filename):
    """ Get absolute path to data files """
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, filename)

def load_or_generate_salt():
    salt_path = get_data_path("salt.key")
    if not os.path.exists(salt_path):
        salt = os.urandom(16)
        with open(salt_path, "wb") as salt_file:
            salt_file.write(salt)
    else:
        with open(salt_path, "rb") as salt_file:
            salt = salt_file.read()
    return salt

def load_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key
