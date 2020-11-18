from hermes.messages.HandShake import HandShake
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from hermes.messages.UDPMessage import UDPMessage
import cryptography
import pytest


def test_new_hand_shakecan_be_created_with_correct_role():
    # Given
    server_role = HandShake.SERVER
    client_role = HandShake.CLIENT
    secret = Fernet.generate_key()

    # When
    server = HandShake(role=server_role, secret=secret)
    client = HandShake(role=client_role)

    # Then
    assert server.role == server_role
    assert client.role == client_role


def test_new_hand_shakecan_be_created_with_correct_hash_pass():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    secret = Fernet.generate_key()

    # When
    sm = HandShake(hash_pass=hash_pass, secret=secret)

    # Then
    assert sm._hash_pass == hash_pass


def test_new_hand_shakecan_be_created_with_correct_secret():
    # Given
    secret = Fernet.generate_key()

    # When
    cm = HandShake(secret=secret)

    # Then
    assert cm._secret == secret


def test_new_hand_shakeis_created_with_a_new_rsa_key():
    # Given
    secret = Fernet.generate_key()
    expected_type = cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey

    # When
    cm = HandShake(secret=secret)

    # Then
    assert isinstance(cm._rsa_key, expected_type)


def test_next_message_returns_correct_message_when_connection_request_begins_and_cm_is_client():
    # Given
    role = HandShake.CLIENT
    cm = HandShake(role=role)
    expected_message = UDPMessage(msg_id=HandShake.GET_PUBLIC_KEY_ID)

    # When
    result = cm.next_message()

    # Then
    assert result.payload == expected_message.payload
    assert result.msg_id == expected_message.msg_id


def test_next_message_returns_none_when_no_connection_request_and_cm_is_server():
    # Given
    role = HandShake.SERVER
    secret = Fernet.generate_key()
    cm = HandShake(role=role, secret=secret)
    expected_message = None

    # When
    result = cm.next_message()

    # Then
    assert result == expected_message


def test_add_message_set_send_public_key_to_true_when_a_get_public_key_request_is_received():
    # Given
    role = HandShake.CLIENT
    cm = HandShake(role=role)
    expected_value = True

    # When
    cm.add_message(cm.next_message())

    # Then
    assert cm._send_public_key == expected_value


def test_next_message_returns_a_message_with_the_public_key_when_cm_is_server_and_send_public_key_is_true():
    # Given
    role = HandShake.SERVER
    secret = Fernet.generate_key()
    cm = HandShake(role=role, secret=secret)
    cm._send_public_key = True
    expected_payload = cm._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # When
    result = cm.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == HandShake.PUT_PUBLIC_KEY_ID
    assert result.payload == expected_payload
    assert cm._send_public_key is False


def test_add_message_correctly_set_remote_host_key_when_a_public_key_is_received():
    # Given
    role = HandShake.CLIENT
    cm = HandShake(role=role)
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
    result = HandShake._get_random_bytes(length)

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
    cm = HandShake(hash_pass=hash_pass, secret=secret)
    cm._remote_host_key = cm._rsa_key.public_key()
    # When
    result = cm._get_password_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, HandShake.RSA_PADDING)[
           HandShake.RANDOM_NUMBER_LEN:] == hash_pass


def test_next_message_return_password_message_when_remote_host_key_is_not_none():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    role = HandShake.CLIENT
    cm = HandShake(role=role, hash_pass=hash_pass)
    cm._remote_host_key = cm._rsa_key.public_key()

    # When
    result = cm.next_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, HandShake.RSA_PADDING)[
           HandShake.RANDOM_NUMBER_LEN:] == hash_pass


def test_add_message_accept_connection_when_hash_pass_is_correct():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    secret = Fernet.generate_key()

    client = HandShake(role=HandShake.CLIENT, hash_pass=hash_pass)
    server = HandShake(role=HandShake.SERVER, hash_pass=hash_pass, secret=secret)

    client._remote_host_key = server._rsa_key.public_key()
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

    client = HandShake(role=HandShake.CLIENT, hash_pass=hash_pass_client)
    server = HandShake(role=HandShake.SERVER, hash_pass=hash_pass_server, secret=secret)

    client._remote_host_key = server._rsa_key.public_key()

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

    client = HandShake(role=HandShake.CLIENT, hash_pass=hash_pass_client)
    server = HandShake(role=HandShake.SERVER, hash_pass=hash_pass_server, secret=secret)

    client._remote_host_key = server._rsa_key.public_key()
    server.add_message(client.next_message())

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == HandShake.END_CONNECTION_ID


def test_next_message_is_get_public_key_when_given_password_is_correct():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()
    secret = Fernet.generate_key()

    client = HandShake(role=HandShake.CLIENT, hash_pass=hash_pass)
    server = HandShake(role=HandShake.SERVER, hash_pass=hash_pass, secret=secret)

    client._remote_host_key = server._rsa_key.public_key()
    server.add_message(client.next_message())

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == HandShake.GET_PUBLIC_KEY_ID


def test_get_key_message_return_key_message_encrypted_with_client_public_key():
    # Given
    secret = Fernet.generate_key()
    role = HandShake.SERVER
    cm = HandShake(role=role, secret=secret)
    cm._remote_host_key = cm._rsa_key.public_key()

    # When

    result = cm._get_secret_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, HandShake.RSA_PADDING)[
           HandShake.RANDOM_NUMBER_LEN:] == secret


def test_next_message_return_key_message_when_password_is_correct_and_remote_host_key_is_not_none_and_role_is_server():
    # Given
    secret = Fernet.generate_key()
    role = HandShake.SERVER
    cm = HandShake(role=role, secret=secret)
    cm._remote_host_key = cm._rsa_key.public_key()
    cm._password_correct = True
    # When
    result = cm.next_message()

    # Then
    assert cm._rsa_key.decrypt(result.payload, HandShake.RSA_PADDING)[
           HandShake.RANDOM_NUMBER_LEN:] == secret


def test_hash_pass_correctly_return_hash_password():
    # Given
    password = b"test"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password)
    hash_pass = digest.finalize()

    # When
    result = HandShake.hash_password(password)

    # Then
    assert result == hash_pass


def test_new_hand_shakeraise_error_when_role_is_server_and_secret_is_none():
    # Given
    role = HandShake.SERVER

    # When

    # Then
    with pytest.raises(ValueError):
        HandShake(role=role)


def test_hand_shake_can_work_properly_from_beginning_to_password_exchange_when_password_correct():
    # Given
    hash_pass = HandShake.hash_password(b"test")
    secret = Fernet.generate_key()
    server = HandShake(role=HandShake.SERVER, hash_pass=hash_pass, secret=secret)
    client = HandShake(role=HandShake.CLIENT, hash_pass=hash_pass)

    # When
    ask_server_pub_key_msg = client.next_message()
    server.add_message(ask_server_pub_key_msg)
    server_pub_key_msg = server.next_message()
    client.add_message(server_pub_key_msg)
    password_msg = client.next_message()
    server.add_message(password_msg)
    ask_client_pub_key_msg = server.next_message()

    # Then
    assert int.from_bytes(ask_client_pub_key_msg.msg_id, "little") == HandShake.GET_PUBLIC_KEY_ID


def test_hand_shake_can_work_properly_from_beginning_to_password_exchange_when_password_incorrect():
    # Given
    hash_pass_server = HandShake.hash_password(b"test")
    hash_pass_client = HandShake.hash_password(b"incorrect")
    secret = Fernet.generate_key()
    server = HandShake(role=HandShake.SERVER, hash_pass=hash_pass_server, secret=secret)
    client = HandShake(role=HandShake.CLIENT, hash_pass=hash_pass_client)

    # When
    ask_server_pub_key_msg = client.next_message()
    server.add_message(ask_server_pub_key_msg)
    server_pub_key_msg = server.next_message()
    client.add_message(server_pub_key_msg)
    password_msg = client.next_message()
    server.add_message(password_msg)
    ask_client_pub_key_msg = server.next_message()

    # Then
    assert int.from_bytes(ask_client_pub_key_msg.msg_id, "little") == HandShake.END_CONNECTION_ID


def test_hand_shake_can_work_properly_from_beginning_to_secret_exchange_when_password_correct():
    # Given
    hash_pass = HandShake.hash_password(b"test")
    secret = Fernet.generate_key()
    server = HandShake(role=HandShake.SERVER, hash_pass=hash_pass, secret=secret)
    client = HandShake(role=HandShake.CLIENT, hash_pass=hash_pass)

    # When
    ask_server_pub_key_msg = client.next_message()
    server.add_message(ask_server_pub_key_msg)

    server_pub_key_msg = server.next_message()
    client.add_message(server_pub_key_msg)

    password_msg = client.next_message()
    server.add_message(password_msg)

    ask_client_pub_key_msg = server.next_message()
    client.add_message(ask_client_pub_key_msg)

    client_pub_key_msg = client.next_message()
    server.add_message(client_pub_key_msg)

    server_secret_msg = server.next_message()
    client.add_message(server_secret_msg)

    # Then
    assert int.from_bytes(server_secret_msg.msg_id, "little") == HandShake.PUT_SECRET_MESSAGE_ID
    assert client._secret == server._secret

# python -m pytest -s hermes/messages/test/test_HandShake.py
