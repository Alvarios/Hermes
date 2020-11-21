from hermes.security.HandShake_refacto import HandShake
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from hermes.messages.UDPMessage import UDPMessage
import hermes.messages.codes as codes


def test_hand_shake_verify_password_return_true_if_given_password_is_correct_and_role_is_server():
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

    role = HandShake.SERVER

    server = HandShake(role=role, derived_password=derived_password, password_salt=password_salt)
    # When
    result = server.verify_password(password_to_verify=password_to_verify)

    # Then
    assert result == expected_result


def test_hand_shake_verify_password_return_false_if_given_password_is_incorrect_and_role_is_server():
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

    role = HandShake.SERVER

    server = HandShake(role=role, derived_password=derived_password, password_salt=password_salt)
    # When
    result = server.verify_password(password_to_verify=password_to_verify)

    # Then
    assert result == expected_result


def test_hand_shake_verify_password_return_true_in_any_cas_if_no_derived_password_and_role_is_server():
    # Given
    passwords_to_verify = [b"", b"incorrect_password", b"test_password"]
    derived_password = None
    expected_result = True

    role = HandShake.SERVER

    server = HandShake(role=role, derived_password=derived_password)
    # When
    results = [server.verify_password(password_to_verify=password) for password in passwords_to_verify]

    # Then
    for result in results:
        assert result == expected_result


def test_next_message_returns_correct_message_when_connection_request_begins_and_role_is_client():
    # Given
    role = HandShake.CLIENT
    client = HandShake(role=role)
    expected_message = UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_REQUEST_TOPIC)

    # When
    result = client.next_message()

    # Then
    assert result.payload == expected_message.payload
    assert result.msg_id == expected_message.msg_id
    assert result.topic == expected_message.topic


def test_next_message_returns_none_when_no_connection_request_and_cm_is_server():
    # Given
    role = HandShake.SERVER
    server = HandShake(role=role)
    expected_message = None

    # When
    result = server.next_message()

    # Then
    assert result == expected_message


# def test_get_public_key_return_hand_shake_ephemeral_elliptic_curve_public_key():
#     # Given
#     role = HandShake.SERVER
#     server = HandShake(role=role)
#     expected_result = None
#
#     # When
#     result = server.get_public_key()
#
#     # Then
#     assert result == expected_result

# python -m pytest -s hermes/security/tests/test_HandShake_refacto.py -vv
