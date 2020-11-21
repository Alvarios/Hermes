from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey, AlreadyFinalized


def verify_password_scrypt(password_to_verify, derived_password, password_salt):
    """Check if the input password correspond to the instance derived password and salt.

    :param password_to_verify: The password to verify as bytes.
    :param derived_password: The derived password used to verify the given password as bytes.
    :param password_salt: The salt used to derive the password as bytes.

    :return: True if is verified, else False.
    """
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


def derive_password_scrypt(password_to_derive: bytes, password_salt: bytes) -> bytes:
    """Derive a password using scrypt algorithm.

    :param password_to_derive: The password to derive as bytes.
    :param password_salt: The salt (extra random bytes to add noise) to use for password derivation.

    :return: The derived password as bytes.
    """
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    return kdf.derive(password_to_derive)
