from hermes.security.utils import verify_password_scrypt, derive_password_scrypt, derive_key_hkdf, generate_key_32
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


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


def test_derive_key_hkdf_return_a_derived_key_of_correct_length():
    # Given
    expected_lengths = [2, 4, 8, 16, 32, 64]
    key_to_derive = b"01234567890123456789012346789012345678912345678"
    # When
    results = [derive_key_hkdf(key=key_to_derive, length=length) for length in expected_lengths]

    # Then
    for result_length in zip(results, expected_lengths):
        assert len(result_length[0]) == result_length[1]


def test_derive_key_hkdf_return_exactly_the_same_key_than_hkdf_derivation_if_same_input():
    # Given
    algorithm = hashes.SHA3_256()
    length = 32
    salt = b''
    info = b"test"
    key_to_derive = b"01234567890123456789012346789012345678912345678"

    expected_result = HKDF(
        algorithm=algorithm,
        length=length,
        salt=salt,
        info=info,
    ).derive(key_to_derive)

    # When
    result = derive_key_hkdf(key=key_to_derive, length=length, salt=salt, info=info, algorithm=algorithm)

    # Then
    assert result == expected_result


def test_generate_key_32_create_a_key_of_32_bytes():
    # Given
    expected_length = 32

    # When
    result = generate_key_32()

    # Then
    assert len(result) == expected_length
    assert type(result) == bytes


def test_generate_key_create_different_key_when_called_multiple_times():
    # Given
    baseline = generate_key_32()

    # When
    result = generate_key_32()
    if result == baseline:
        result = generate_key_32()

    # Then
    assert baseline != result


def test_generate_key_32_can_create_key_from_input_key():
    # Given
    key1 = b"test"
    key2 = b"another_test"
    baseline = generate_key_32(key1)

    # When
    result1 = generate_key_32(key1)
    result2 = generate_key_32(key2)

    # Then
    assert baseline == result1
    assert baseline != result2

# python -m pytest -s hermes/security/tests/test_utils.py -vv
