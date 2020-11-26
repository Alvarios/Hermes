from hermes.security.HandShake import HandShake
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from hermes.messages.UDPMessage import UDPMessage
import hermes.messages.codes as codes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hermes.security.utils import derive_password_scrypt
import json
import pytest
import time
import base64


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
    result = server._verify_password(password_to_verify=password_to_verify)

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
    result = server._verify_password(password_to_verify=password_to_verify)

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
    results = [server._verify_password(password_to_verify=password) for password in passwords_to_verify]

    # Then
    for result in results:
        assert result == expected_result


def test_next_message_returns_correct_message_when_connection_request_begins_and_role_is_client():
    # Given
    role = HandShake.CLIENT
    client = HandShake(role=role)
    expected_id = codes.HANDSHAKE
    expected_topic = HandShake.CONNECTION_REQUEST_TOPIC

    # When
    result = client.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic


def test_next_message_returns_none_when_no_connection_request_and_cm_is_server():
    # Given
    role = HandShake.SERVER
    server = HandShake(role=role)
    expected_message = None

    # When
    result = server.next_message()

    # Then
    assert result == expected_message


def test_next_message_return_a_message_with_an_ec_public_key_when_connection_step_2_and_role_is_server():
    # Given
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)
    expected_result_pub_key = bytes.decode(
        server._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PublicFormat.
                                                      SubjectPublicKeyInfo), "ascii")
    server.add_message(client.next_message())
    # When
    result = server.next_message()
    result_payload = json.loads(bytes.decode(result.payload, "utf8"))

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == HandShake.SERVER_KEY_SHARE_TOPIC
    assert result_payload[HandShake.SERVER_PUBLIC_KEY_KEY_NAME] == expected_result_pub_key


def test_next_message_return_a_message_with_an_ec_public_key_when_connection_step_3_and_role_is_client():
    # Given
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)
    expected_result_payload = client._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                            format=serialization.PublicFormat.
                                                                            SubjectPublicKeyInfo)
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    # When
    result = client.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == HandShake.CLIENT_KEY_SHARE_TOPIC
    assert result.payload == expected_result_payload


def test_both_server_and_client_can_generate_shared_key_when_peer_public_key_has_been_received():
    # Given
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)
    expected_shared_key = server._private_key.exchange(ec.ECDH(), client._private_key.public_key())

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    server_secret = server.get_shared_key()
    client_secret = client.get_shared_key()

    # Then
    assert expected_shared_key == server_secret == client_secret


def test_next_message_return_connection_approved_message_when_connection_step_4_and_role_is_server_and_no_password():
    # Given
    allowed_authentication_method = []
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    expected_message = UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_APPROVED_TOPIC)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert result.msg_id == expected_message.msg_id
    assert result.topic == expected_message.topic


def test_next_message_return_authentication_required_message_when_connection_step_4_and_role_is_server_with_password():
    # Given
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    expected_message = UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.AUTHENTICATION_REQUIRED_TOPIC)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert result.msg_id == expected_message.msg_id
    assert result.topic == expected_message.topic


def test_decrypt_can_decrypt_messages_encrypted_with_encrypt_when_connection_step_4_for_both_roles():
    # Given
    msg_to_encrypt = b"A very secret message"
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When

    encrypt_server = server._encrypt(data=msg_to_encrypt)
    encrypt_client = client._encrypt(data=msg_to_encrypt)
    decrypted_server = server._decrypt(encrypt_server)
    decrypted_client = client._decrypt(encrypt_client)

    # Then
    assert decrypted_client == decrypted_server == msg_to_encrypt


def test_encrypt_return_different_bytes_than_input_when_connection_step_4_for_both_roles():
    # Given
    msg_to_encrypt = b"A very secret message"
    password_salt = os.urandom(16)
    password_to_derive = b"test"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When

    encrypt_server = server._encrypt(data=msg_to_encrypt)
    encrypt_client = client._encrypt(data=msg_to_encrypt)

    # Then
    assert encrypt_client != msg_to_encrypt
    assert encrypt_server != msg_to_encrypt


def test_next_message_return_authentication_message_when_connection_step_4_and_role_is_client_with_password():
    # Given
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=password_to_derive)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    expected_id = codes.HANDSHAKE
    expected_topic = HandShake.AUTHENTICATION_TOPIC

    # When
    result = client.next_message()
    payload = json.loads(bytes.decode(result.payload, "utf8"))
    password = base64.b64decode(str.encode(payload[HandShake.PASSWORD_AUTH_METHOD_PASSWORD_KEY], 'ascii'))

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic

    assert server._decrypt(password) == password_to_derive


def test_next_message_return_connection_approved_message_when_connection_step_6_and_role_is_server_and_password_ok():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=password_to_derive)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())

    expected_id = codes.HANDSHAKE
    expected_topic = HandShake.CONNECTION_APPROVED_TOPIC

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic


def test_next_message_return_connection_failed_msg_when_connection_step_6_and_role_is_client_and_password_incorrect():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test"
    password_client = b"incorrect"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=password_client)

    expected_id = codes.HANDSHAKE
    expected_topic = HandShake.CONNECTION_FAILED_TOPIC

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic


def test_connection_request_message_contains_a_list_of_available_protocols():
    # Given
    role = HandShake.CLIENT
    client = HandShake(role=role)
    expected_message = UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_REQUEST_TOPIC)
    connection_request_message = client.next_message()

    # When
    result = json.loads(bytes.decode(connection_request_message.payload, "utf8"))

    # Then
    assert HandShake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME in result.keys()
    assert type(result[HandShake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME]) is list
    assert len(result[HandShake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME]) > 0
    assert result[HandShake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME][0] == "alpha"
    assert result[HandShake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME] == HandShake.PROTOCOL_VERSIONS_AVAILABLE


def test_authentication_required_message_contain_a_list_of_authentication_methods_available():
    # Given
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=password_to_derive)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    authentication_required_message = server.next_message()

    # When
    result = json.loads(bytes.decode(authentication_required_message.payload, "utf8"))

    # Then
    assert HandShake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME in result.keys()
    assert type(result[HandShake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME]) is list
    assert len(result[HandShake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME]) > 0
    assert result[HandShake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME] == HandShake.AUTHENTICATION_METHODS_AVAILABLE


def test_get_status_return_incomplete_when_role_is_client_and_handshake_process_not_started():
    # Given
    role = HandShake.CLIENT
    client = HandShake(role=role)

    # When
    result = client.get_status()

    # Then
    assert result == HandShake.CONNECTION_STATUS_INCOMPLETE


def test_get_status_return_complete_when_and_handshake_was_successful_without_authentication():
    # Given
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    result_client = client.get_status()
    result_server = server.get_status()

    # Then
    assert result_client == HandShake.CONNECTION_STATUS_APPROVED
    assert result_server == HandShake.CONNECTION_STATUS_APPROVED


def test_get_status_return_failed_when_authentication_is_incorrect():
    # Given
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    password_client = b"incorrect"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_methods = ["password"]
    client = HandShake(role=HandShake.CLIENT, authentication_information=password_client,
                       allowed_authentication_methods=allowed_authentication_methods)
    server = HandShake(role=HandShake.SERVER, password_salt=password_salt, derived_password=derived_password,
                       allowed_authentication_methods=allowed_authentication_methods)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    result_client = client.get_status()
    result_server = server.get_status()

    # Then
    assert result_client == HandShake.CONNECTION_STATUS_FAILED
    assert result_server == HandShake.CONNECTION_STATUS_FAILED


def test_get_status_return_approved_when_authentication_is_correct():
    # Given
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    password_client = b"test"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    server = HandShake(role=HandShake.SERVER, password_salt=password_salt, derived_password=derived_password)
    client = HandShake(role=HandShake.CLIENT, authentication_information=password_client)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    result_client = client.get_status()
    result_server = server.get_status()

    # Then
    assert result_client == HandShake.CONNECTION_STATUS_APPROVED
    assert result_server == HandShake.CONNECTION_STATUS_APPROVED


def test_server_key_share_message_contain_selected_protocol_version_which_is_the_latest_available():
    # Given
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert HandShake.SELECTED_PROTOCOL_VERSION_KEY_NAME in result.keys()
    assert result[HandShake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == HandShake.PROTOCOL_VERSIONS_AVAILABLE[-1]


def test_allowed_protocols_versions_can_be_defined_to_only_1_dot_0_when_handshake_is_created():
    # Given
    allowed_protocol_versions = ['1.0']
    server = HandShake(role=HandShake.SERVER, allowed_protocol_versions=allowed_protocol_versions)

    # When
    result = server.get_allowed_protocol_versions()

    # Then
    assert result == allowed_protocol_versions


def test_allowed_protocols_versions_can_be_defined_to_only_alpha_when_handshake_is_created():
    # Given
    allowed_protocol_versions = ['alpha']
    server = HandShake(role=HandShake.SERVER, allowed_protocol_versions=allowed_protocol_versions)

    # When
    result = server.get_allowed_protocol_versions()

    # Then
    assert result == allowed_protocol_versions


def test_allowed_protocols_versions_default_value_is_all_available_protocol_versions():
    # Given
    server = HandShake(role=HandShake.SERVER)

    # When
    result = server.get_allowed_protocol_versions()

    # Then
    assert result == HandShake.PROTOCOL_VERSIONS_AVAILABLE


def test_handshake_raise_value_error_if_a_version_label_provided_does_not_exist():
    # Given
    allowed_protocol_versions = ['alpha', 'test_version_that_does_not_exist']

    # When

    # Then
    with pytest.raises(ValueError):
        server = HandShake(role=HandShake.SERVER, allowed_protocol_versions=allowed_protocol_versions)


def test_server_key_share_message_inform_selected_protocol_is_alpha_if_it_is_the_only_available_for_client():
    # Given
    allowed_protocol_versions = ['alpha']
    expected_result = "alpha"
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT, allowed_protocol_versions=allowed_protocol_versions)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert result[HandShake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == expected_result


def test_server_key_share_message_inform_selected_protocol_is_1_dot_0_if_clients_allowed_protocol_not_sorted():
    # Given
    allowed_protocol_versions = ['1.0', 'alpha']
    expected_result = "1.0"
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT, allowed_protocol_versions=allowed_protocol_versions)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert result[HandShake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == expected_result


def test_server_key_share_message_inform_selected_protocol_is_alpha_if_it_is_the_only_available_for_server():
    # Given
    allowed_protocol_versions = ['alpha']
    expected_result = "alpha"
    server = HandShake(role=HandShake.SERVER, allowed_protocol_versions=allowed_protocol_versions)
    client = HandShake(role=HandShake.CLIENT)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert result[HandShake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == expected_result


def test_connection_fail_if_server_and_client_have_not_a_common_protocol_version():
    # Given
    allowed_protocol_versions_client = ['alpha']
    allowed_protocol_versions_server = ['1.0']
    server = HandShake(role=HandShake.SERVER, allowed_protocol_versions=allowed_protocol_versions_server)
    client = HandShake(role=HandShake.CLIENT, allowed_protocol_versions=allowed_protocol_versions_client)

    server.add_message(client.next_message())

    # When
    connection_failed_message = server.next_message()
    client.add_message(connection_failed_message)

    # Then
    assert server.get_status() == HandShake.CONNECTION_STATUS_FAILED
    assert client.get_status() == HandShake.CONNECTION_STATUS_FAILED
    assert int.from_bytes(connection_failed_message.topic, 'little') == HandShake.CONNECTION_FAILED_TOPIC


def test_connection_fail_if_abort_is_called_on_server_after_a_connection_request():
    # Given

    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)

    server.add_message(client.next_message())

    # When
    server.abort()
    connection_failed_message = server.next_message()
    client.add_message(connection_failed_message)

    # Then
    assert server.get_status() == HandShake.CONNECTION_STATUS_FAILED
    assert client.get_status() == HandShake.CONNECTION_STATUS_FAILED
    assert int.from_bytes(connection_failed_message.topic, 'little') == HandShake.CONNECTION_FAILED_TOPIC


def test_connection_fail_if_abort_is_called_on_client_after_a_connection_request():
    # Given
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)

    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    client.abort()
    connection_failed_message = client.next_message()
    server.add_message(connection_failed_message)

    # Then
    assert server.get_status() == HandShake.CONNECTION_STATUS_FAILED
    assert client.get_status() == HandShake.CONNECTION_STATUS_FAILED
    assert int.from_bytes(connection_failed_message.topic, 'little') == HandShake.CONNECTION_FAILED_TOPIC


def test_time_creation_return_handshake_time_of_creation():
    # Given
    time_test_start = time.time()
    time.sleep(.001)
    client = HandShake(role=HandShake.CLIENT)
    time.sleep(.001)

    # When
    result = client.time_creation()

    # Then
    assert time_test_start < client.time_creation() < time.time()


def test_authentication_message_contain_the_selected_authentication_method_key():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test_password"
    allowed_authentication_methods = ["password"]
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    server = HandShake(role=HandShake.SERVER, password_salt=password_salt, derived_password=derived_password,
                       allowed_authentication_methods=allowed_authentication_methods)
    client = HandShake(role=HandShake.CLIENT, authentication_information=password_to_derive,
                       allowed_authentication_methods=allowed_authentication_methods)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    authentication_message = client.next_message()

    # When
    result = json.loads(bytes.decode(authentication_message.payload, "utf8"))

    # Then
    assert HandShake.SELECTED_AUTHENTICATION_METHOD_KEY_NAME in result.keys()


def test_no_authentication_is_required_when_no_allowed_authentication_method_provided():
    # Given
    allowed_authentication_method = []
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_method)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == HandShake.CONNECTION_APPROVED_TOPIC


def test_allowed_authentication_methods_default_value_is_no_authentication():
    # Given
    server = HandShake(role=HandShake.SERVER)
    client = HandShake(role=HandShake.CLIENT)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == HandShake.CONNECTION_APPROVED_TOPIC


def test_authentication_is_required_if_password_is_provided_as_authentication_method():
    # Given
    allowed_authentication_methods = ["password"]
    server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_methods)
    client = HandShake(role=HandShake.CLIENT, allowed_authentication_methods=allowed_authentication_methods)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == HandShake.AUTHENTICATION_REQUIRED_TOPIC


def test_handshake_raise_value_error_if_a_authentication_method_provided_does_not_exist():
    # Given
    allowed_authentication_methods = ['password', 'authentication_method_that_does_not_exist']

    # When

    # Then
    with pytest.raises(ValueError):
        server = HandShake(role=HandShake.SERVER, allowed_authentication_methods=allowed_authentication_methods)

# python -m pytest -s hermes/security/tests/test_HandShake.py -vv
