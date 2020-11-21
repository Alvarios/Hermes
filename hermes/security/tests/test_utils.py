from hermes.security.utils import verify_password_scrypt, derive_password_scrypt
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def test_verify_password_scrypt_return_true_if_given_password_is_correct_and_derived_with_scrypt():
    # Given
    password_to_verify = b"test_password"
    password_to_derive = b"test_password"
    password_salt = os.urandom(16)
    expected_result = True

    # derive
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    derived_password = kdf.derive(password_to_derive)

    # When
    result = verify_password_scrypt(password_to_verify=password_to_verify, derived_password=derived_password,
                                    password_salt=password_salt)

    # Then
    assert result == expected_result


def test_verify_password_scrypt_return_false_if_given_password_is_incorrect_and_derived_with_scrypt():
    # Given
    password_to_verify = b"incorrect_password"
    password_to_derive = b"test_password"
    password_salt = os.urandom(16)
    expected_result = False

    # derive
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    derived_password = kdf.derive(password_to_derive)

    # When
    result = verify_password_scrypt(password_to_verify=password_to_verify, derived_password=derived_password,
                                    password_salt=password_salt)

    # Then
    assert result == expected_result


def test_derive_password_scrypt_correctly_derive_a_password_with_scrypt():
    # Given
    password_to_verify = b"test_password"
    password_to_derive = b"test_password"
    password_salt = os.urandom(16)

    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    expected_result = kdf.derive(password_to_verify)

    # When
    result = derive_password_scrypt(password_to_derive, password_salt)

    # Then
    assert result == expected_result

# python -m pytest -s hermes/security/tests/test_utils.py -vv
