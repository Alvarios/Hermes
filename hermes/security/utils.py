from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey, AlreadyFinalized


def verify_password_scrypt(password_to_verify, derived_password, password_salt):
    password_correct = False
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    try:
        kdf.verify(password_to_verify, derived_password)
        password_correct = True
    except InvalidKey:
        pass
    except AlreadyFinalized:
        pass
    return password_correct


def derive_password_scrypt(password_to_derive, password_salt):
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    return kdf.derive(password_to_derive)
