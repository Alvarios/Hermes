import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# print(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,
#                         encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase")))

# r = requests.get('http://127.0.0.1:5000/')
# print(r.content)

msg = bytes("test", encoding="ascii")
key = Fernet.generate_key()
print(type(key))
f = Fernet(key)
msg_crypt = f.encrypt(msg)
msg_decrypt = f.decrypt(msg_crypt)
print(msg)
print(msg_crypt)
print(msg_decrypt)
