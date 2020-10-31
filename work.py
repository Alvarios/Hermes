from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generate our key
key: rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pub_key = key.public_key()
tst = pub_key.public_bytes(encoding=serialization.Encoding.PEM,
                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
tst = serialization.load_pem_public_key(tst)

print(tst)

msg = "hello, world".encode("utf8")

encoded_msg = tst.encrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))

print(encoded_msg)
print(len(encoded_msg))

plaintext = key.decrypt(
    encoded_msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(msg)
print(hashes.Hash())
