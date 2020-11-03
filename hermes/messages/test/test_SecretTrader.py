from hermes.messages.SecretTrader import SecretTrader
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from hermes.messages.UDPMessage import UDPMessage
import cryptography
import pytest


def test_new_secret_trader_can_be_created_with_correct_role():
    # Given
    server = SecretTrader.SERVER
    client = SecretTrader.CLIENT
    secret = Fernet.generate_key()

    # When
    cm_server = SecretTrader(role=server, secret=secret)
    cm_client = SecretTrader(role=client)

    # Then
    assert cm_server.role == server
    assert cm_client.role == client


def test_new_secret_trader_can_be_created_with_correct_hash_pass():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    secret = Fernet.generate_key()

    # When
    cm = SecretTrader(hash_pass=hash_pass, secret=secret)

    # Then
    assert cm._hash_pass == hash_pass


def test_new_secret_trader_can_be_created_with_correct_secret():
    # Given
    secret = Fernet.generate_key()

    # When
    cm = SecretTrader(secret=secret)

    # Then
    assert cm._secret == secret


def test_new_secret_trader_is_created_with_a_new_rsa_key():
    # Given
    secret = Fernet.generate_key()
    expected_type = cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey

    # When
    cm = SecretTrader(secret=secret)

    # Then
    assert isinstance(cm._rsa_key, expected_type)


def test_next_message_returns_correct_message_when_connection_request_begins_and_cm_is_client():
    # Given
    role = SecretTrader.CLIENT
    cm = SecretTrader(role=role)
    expected_message = UDPMessage(msg_id=SecretTrader.GET_PUBLIC_KEY_ID)

    # When
    result = cm.next_message()

    # Then
    assert result.payload == expected_message.payload
    assert result.msg_id == expected_message.msg_id


def test_next_message_returns_none_when_no_connection_request_and_cm_is_server():
    # Given
    role = SecretTrader.SERVER
    secret = Fernet.generate_key()
    cm = SecretTrader(role=role, secret=secret)
    expected_message = None

    # When
    result = cm.next_message()

    # Then
    assert result == expected_message


def test_add_message_set_send_public_key_to_true_when_a_get_public_key_request_is_received():
    # Given
    role = SecretTrader.CLIENT
    cm = SecretTrader(role=role)
    expected_value = True

    # When
    cm.add_message(cm.next_message())

    # Then
    assert cm._send_public_key == expected_value


def test_next_message_returns_a_message_with_the_public_key_when_cm_is_server_and_send_public_key_is_true():
    # Given
    role = SecretTrader.SERVER
    secret = Fernet.generate_key()
    cm = SecretTrader(role=role, secret=secret)
    cm._send_public_key = True
    expected_payload = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # When
    result = cm.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == SecretTrader.PUT_PUBLIC_KEY_ID
    assert result.payload == expected_payload
    assert cm._send_public_key is False


def test_add_message_correctly_set_remote_host_key_when_a_public_key_is_received():
    # Given
    role = SecretTrader.CLIENT
    cm = SecretTrader(role=role)
    expected_value = cm._rsa_key.public_key()

    cm._send_public_key = True

    # When
    cm.add_message(cm.next_message())

    # Then
    assert cm._remote_host_key.public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.
                                            SubjectPublicKeyInfo) == expected_value.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.
            SubjectPublicKeyInfo)


def test_get_random_bytes_return_bytes_with_correct_length():
    # Given
    length = 50

    # When
    result = SecretTrader._get_random_bytes(length)

    # Then
    assert type(result) is bytes
    assert len(result) == length


def test_get_password_message_correctly_return_a_udp_message_with_hash_pass():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    secret = Fernet.generate_key()
    cm = SecretTrader(hash_pass=hash_pass, secret=secret)
    cm._remote_host_key = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.
                                                                SubjectPublicKeyInfo)

    # When
    result = cm._get_password_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, SecretTrader.RSA_PADDING)[
           SecretTrader.RANDOM_NUMBER_LEN:] == hash_pass


def test_next_message_return_password_message_when_remote_host_key_is_not_none():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    role = SecretTrader.CLIENT
    cm = SecretTrader(role=role, hash_pass=hash_pass)
    cm._remote_host_key = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # When
    result = cm.next_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, SecretTrader.RSA_PADDING)[
           SecretTrader.RANDOM_NUMBER_LEN:] == hash_pass


def test_add_message_accept_connection_when_hash_pass_is_correct():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    secret = Fernet.generate_key()

    client = SecretTrader(role=SecretTrader.CLIENT, hash_pass=hash_pass)
    server = SecretTrader(role=SecretTrader.SERVER, hash_pass=hash_pass, secret=secret)

    client._remote_host_key = server._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)
    # When
    server.add_message(client.next_message())

    # Then
    assert server._password_correct is True


def test_add_message_reject_connection_when_hash_pass_is_incorrect():
    # Given
    password_client = b"incorrect"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password_client)
    hash_pass_client = digest.finalize()

    password_server = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password_server)
    hash_pass_server = digest.finalize()
    secret = Fernet.generate_key()

    client = SecretTrader(role=SecretTrader.CLIENT, hash_pass=hash_pass_client)
    server = SecretTrader(role=SecretTrader.SERVER, hash_pass=hash_pass_server, secret=secret)

    client._remote_host_key = server._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)

    # When
    server.add_message(client.next_message())

    # Then
    assert server._password_correct is False


def test_next_message_is_end_connection_when_given_password_is_incorrect():
    # Given
    password_client = b"incorrect"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password_client)
    hash_pass_client = digest.finalize()

    password_server = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password_server)
    hash_pass_server = digest.finalize()
    secret = Fernet.generate_key()

    client = SecretTrader(role=SecretTrader.CLIENT, hash_pass=hash_pass_client)
    server = SecretTrader(role=SecretTrader.SERVER, hash_pass=hash_pass_server, secret=secret)

    client._remote_host_key = server._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)
    server.add_message(client.next_message())

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == SecretTrader.END_CONNECTION_ID


def test_next_message_is_get_public_key_when_given_password_is_correct():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    secret = Fernet.generate_key()

    client = SecretTrader(role=SecretTrader.CLIENT, hash_pass=hash_pass)
    server = SecretTrader(role=SecretTrader.SERVER, hash_pass=hash_pass, secret=secret)

    client._remote_host_key = server._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)
    server.add_message(client.next_message())

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == SecretTrader.GET_PUBLIC_KEY_ID


def test_get_key_message_return_key_message_encrypted_with_client_public_key():
    # Given
    secret = Fernet.generate_key()
    role = SecretTrader.SERVER
    cm = SecretTrader(role=role, secret=secret)
    cm._remote_host_key = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # When

    result = cm._get_key_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, SecretTrader.RSA_PADDING)[
           SecretTrader.RANDOM_NUMBER_LEN:] == secret


def test_next_message_return_key_message_when_password_is_correct_and_remote_host_key_is_not_none_and_role_is_server():
    # Given
    secret = Fernet.generate_key()
    role = SecretTrader.SERVER
    cm = SecretTrader(role=role, secret=secret)
    cm._remote_host_key = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
    cm._password_correct = True
    # When
    result = cm.next_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, SecretTrader.RSA_PADDING)[
           SecretTrader.RANDOM_NUMBER_LEN:] == secret


def test_hash_pass_correctly_return_hash_password():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()

    # When
    result = SecretTrader.hash_password(password)

    # Then
    assert result == hash_pass


def test_new_secret_trader_raise_error_when_role_is_server_and_secret_is_none():
    # Given
    role = SecretTrader.SERVER

    # When

    # Then
    with pytest.raises(ValueError):
        SecretTrader(role=role)

# python -m pytest -s hermes/messages/test/test_SecretTrader.py
