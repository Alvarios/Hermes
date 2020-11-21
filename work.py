# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import os
#
# nonce = os.urandom(16)
# algorithm = algorithms.ChaCha20(key, nonce)
# cipher = Cipher(algorithm, mode=None)
# encryptor = cipher.encryptor()
# ct = encryptor.update(b"a secret message")
# decryptor = cipher.decryptor()
# decryptor.update(ct)

#
# import os
# from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
#
# data = b"a secret message"
# # aad = b"authenticated but unencrypted data"
# aad = None
# key = ChaCha20Poly1305.generate_key()
#
# chacha = ChaCha20Poly1305(key)
# nonce = os.urandom(12)
# ct = chacha.encrypt(nonce, data, aad)
# print(ct)
# print(len(ct))
#
# print(chacha.decrypt(nonce, ct, aad))

# import os
# from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
# from cryptography.exceptions import InvalidKey, AlreadyFinalized
#
# salt = os.urandom(16)
# # derive
# kdf = Scrypt(
#     salt=salt,
#     length=32,
#     n=2 ** 14,
#     r=8,
#     p=1,
# )
# key = kdf.derive(b"my great password")
# print(type(key))
#
# # verify
# kdf = Scrypt(
#     salt=salt,
#     length=32,
#     n=2 ** 14,
#     r=8,
#     p=1,
# )
#
# password_correct = False
# try:
#     kdf.verify(b"my great password", key)
#     password_correct = True
# except InvalidKey:
#     pass
# except AlreadyFinalized:
#     pass
# print(password_correct)

# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
#
# # Generate a private key for use in the exchange.
# private_key = ec.generate_private_key(
#     ec.SECP384R1()
# )
# # In a real handshake the peer_public_key will be received from the
# # other party. For this example we'll generate another private key
# # and get a public key from that.
# peer_public_key = ec.generate_private_key(
#     ec.SECP384R1()
# ).public_key()
#
# shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
# # Perform key derivation.
# derived_key = HKDF(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=None,
#     info=b'handshake data',
# ).derive(shared_key)
# # For the next handshake we MUST generate another private key.
# private_key_2 = ec.generate_private_key(
#     ec.SECP384R1()
# )
# peer_public_key_2 = ec.generate_private_key(
#     ec.SECP384R1()
# ).public_key()
# shared_key_2 = private_key_2.exchange(ec.ECDH(), peer_public_key_2)
# derived_key_2 = HKDF(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=None,
#     info=b'handshake data',
# ).derive(shared_key_2)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Generate a private key for use in the exchange.
server_private_key = ec.generate_private_key(
    ec.SECP384R1()
)
# In a real handshake the peer is a remote client. For this
# example we'll generate another local private key though.
peer_private_key = ec.generate_private_key(
    ec.SECP384R1()
)
shared_key = server_private_key.exchange(
    ec.ECDH(), peer_private_key.public_key())
# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

# And now we can demonstrate that the handshake performed in the
# opposite direction gives the same final value
same_shared_key = peer_private_key.exchange(
    ec.ECDH(), server_private_key.public_key())
# Perform key derivation.
same_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(same_shared_key)


print(derived_key == same_derived_key)
print(type(peer_private_key.public_key()))
print(type(same_shared_key))
print(same_shared_key)
