from hermes.messages.ConnectionManager import ConnectionManager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from hermes.messages.UDPMessage import UDPMessage
import cryptography
import numpy as np


def test_new_connection_manager_can_be_created_with_correct_role():
    # Given
    server = ConnectionManager.SERVER
    client = ConnectionManager.CLIENT

    # When
    cm_server = ConnectionManager(role=server)
    cm_client = ConnectionManager(role=client)

    # Then
    assert cm_server.role == server
    assert cm_client.role == client


def test_new_connection_manager_can_be_created_with_correct_hash_pass():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()

    # When
    cm = ConnectionManager(hash_pass=hash_pass)

    # Then
    assert cm.hash_pass == hash_pass


def test_new_connection_manager_can_be_created_with_correct_encryption_key():
    # Given
    encryption_key = Fernet.generate_key()

    # When
    cm = ConnectionManager(encryption_key=encryption_key)

    # Then
    assert cm.encryption_key == encryption_key


def test_new_connection_manager_is_created_with_a_new_rsa_key():
    # Given
    expected_type = cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey

    # When
    cm = ConnectionManager()

    # Then
    assert isinstance(cm._rsa_key, expected_type)


def test_next_message_returns_correct_message_when_connection_request_begins_and_cm_is_client():
    # Given
    role = ConnectionManager.CLIENT
    cm = ConnectionManager(role=role)
    expected_message = UDPMessage(msg_id=ConnectionManager.GET_PUBLIC_KEY_ID)

    # When
    result = cm.next_message()

    # Then
    assert result.payload == expected_message.payload
    assert result.msg_id == expected_message.msg_id


def test_next_message_returns_none_when_no_connection_request_and_cm_is_server():
    # Given
    role = ConnectionManager.SERVER
    cm = ConnectionManager(role=role)
    expected_message = None

    # When
    result = cm.next_message()

    # Then
    assert result == expected_message


def test_add_message_set_send_public_key_to_true_when_a_get_public_key_request_is_received():
    # Given
    role = ConnectionManager.CLIENT
    cm = ConnectionManager(role=role)
    expected_value = True

    # When
    cm.add_message(cm.next_message())

    # Then
    assert cm._send_public_key == expected_value


def test_next_message_returns_a_message_with_the_public_key_when_cm_is_server_and_send_public_key_is_true():
    # Given
    role = ConnectionManager.SERVER
    cm = ConnectionManager(role=role)
    cm._send_public_key = True
    expected_payload = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # When
    result = cm.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == ConnectionManager.PUT_PUBLIC_KEY_ID
    assert result.payload == expected_payload
    assert cm._send_public_key is False


def test_add_message_correctly_set_remote_host_key_when_a_public_key_is_received():
    # Given
    role = ConnectionManager.CLIENT
    cm = ConnectionManager(role=role)
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
    result = ConnectionManager.get_random_bytes(length)

    # Then
    assert type(result) is bytes
    assert len(result) == length


def test_get_password_message_correctly_return_a_udp_message_with_hash_pass():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    cm = ConnectionManager(hash_pass=hash_pass)

    # When
    result = cm.get_password_message()

    # Then
    assert result.payload[ConnectionManager.RANDOM_NUMBER_LEN:] == hash_pass


def test_next_message_return_password_message_when_remote_host_key_is_not_none():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    role = ConnectionManager.CLIENT
    cm = ConnectionManager(role=role, hash_pass=hash_pass)
    cm._remote_host_key = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # When
    result = cm.next_message()
    result = cm._rsa_key.decrypt(result, ConnectionManager.RSA_PADDING)
    result = UDPMessage.from_bytes(result)

    # Then
    assert result.payload[ConnectionManager.RANDOM_NUMBER_LEN:] == hash_pass


def test_add_message_accept_connection_when_hash_pass_is_correct():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()

    client = ConnectionManager(role=ConnectionManager.CLIENT, hash_pass=hash_pass)
    client._remote_host_key = client._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)
    server = ConnectionManager(role=ConnectionManager.SERVER, hash_pass=hash_pass)

    # When
    msg = client.next_message()
    msg = client._rsa_key.decrypt(msg, ConnectionManager.RSA_PADDING)
    msg = UDPMessage.from_bytes(msg)
    server.add_message(msg)

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

    client = ConnectionManager(role=ConnectionManager.CLIENT, hash_pass=hash_pass_client)
    client._remote_host_key = client._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)

    server = ConnectionManager(role=ConnectionManager.SERVER, hash_pass=hash_pass_server)

    # When
    msg = client.next_message()
    msg = client._rsa_key.decrypt(msg, ConnectionManager.RSA_PADDING)
    msg = UDPMessage.from_bytes(msg)
    server.add_message(msg)

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

    client = ConnectionManager(role=ConnectionManager.CLIENT, hash_pass=hash_pass_client)
    client._remote_host_key = client._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)

    server = ConnectionManager(role=ConnectionManager.SERVER, hash_pass=hash_pass_server)
    msg = client.next_message()
    msg = client._rsa_key.decrypt(msg, ConnectionManager.RSA_PADDING)
    msg = UDPMessage.from_bytes(msg)
    server.add_message(msg)

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == ConnectionManager.END_CONNECTION_ID


def test_next_message_is_get_public_key_when_given_password_is_correct():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()

    client = ConnectionManager(role=ConnectionManager.CLIENT, hash_pass=hash_pass)
    client._remote_host_key = client._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                        format=serialization.PublicFormat.
                                                                        SubjectPublicKeyInfo)
    server = ConnectionManager(role=ConnectionManager.SERVER, hash_pass=hash_pass)

    msg = client.next_message()
    msg = client._rsa_key.decrypt(msg, ConnectionManager.RSA_PADDING)
    msg = UDPMessage.from_bytes(msg)
    server.add_message(msg)

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == ConnectionManager.GET_PUBLIC_KEY_ID

# python -m pytest -s hermes/messages/test/test_ConnectionManager.py
