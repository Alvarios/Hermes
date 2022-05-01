from hermes.security.Handshake import Handshake
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from hermes.messages.UDPMessage import UDPMessage
import hermes.domain.MessageCodes as codes
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
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    allowed_authentication_methods = ["password"]
    server = Handshake(role=Handshake.SERVER, authentication_information=authentication_information_server,
                       allowed_authentication_methods=allowed_authentication_methods)
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
    allowed_authentication_methods = ["password"]

    # derive
    kdf = Scrypt(
        salt=password_salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    derived_password = kdf.derive(password_to_derive)

    role = Handshake.SERVER
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=role, authentication_information=authentication_information_server,
                       allowed_authentication_methods=allowed_authentication_methods)
    # When
    result = server._verify_password(password_to_verify=password_to_verify)

    # Then
    assert result == expected_result


def test_hand_shake_verify_password_return_true_in_any_cas_if_no_derived_password_and_role_is_server():
    # Given
    allowed_authentication_methods = ["password"]
    passwords_to_verify = [b"", b"incorrect_password", b"test_password"]
    derived_password = None
    expected_result = True

    role = Handshake.SERVER
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: None}}

    server = Handshake(role=role, authentication_information=authentication_information_server,
                       allowed_authentication_methods=allowed_authentication_methods)
    # When
    results = [server._verify_password(password_to_verify=password) for password in passwords_to_verify]

    # Then
    for result in results:
        assert result == expected_result


def test_next_message_returns_correct_message_when_connection_request_begins_and_role_is_client():
    # Given
    role = Handshake.CLIENT
    client = Handshake(role=role)
    expected_id = codes.HANDSHAKE
    expected_topic = Handshake.CONNECTION_REQUEST_TOPIC

    # When
    result = client.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic


def test_next_message_returns_none_when_no_connection_request_and_cm_is_server():
    # Given
    role = Handshake.SERVER
    server = Handshake(role=role)
    expected_message = None

    # When
    result = server.next_message()

    # Then
    assert result == expected_message


def test_next_message_return_a_message_with_an_ec_public_key_when_connection_step_2_and_role_is_server():
    # Given
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)
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
    assert int.from_bytes(result.topic, 'little') == Handshake.SERVER_KEY_SHARE_TOPIC
    assert result_payload[Handshake.SERVER_PUBLIC_KEY_KEY_NAME] == expected_result_pub_key


def test_next_message_return_a_message_with_an_ec_public_key_when_connection_step_3_and_role_is_client():
    # Given
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)
    expected_result_public_key = client._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                               format=serialization.PublicFormat.
                                                                               SubjectPublicKeyInfo)
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    # When
    result = client.next_message()
    payload = json.loads(bytes.decode(result.payload, "utf8"))
    result_public_key = str.encode(payload[Handshake.CLIENT_PUBLIC_KEY_KEY_NAME], 'ascii')

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == Handshake.CLIENT_KEY_SHARE_TOPIC
    assert result_public_key == expected_result_public_key


def test_both_server_and_client_can_generate_shared_key_when_peer_public_key_has_been_received():
    # Given
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)
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
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    expected_message = UDPMessage(code=codes.HANDSHAKE, topic=Handshake.CONNECTION_APPROVED_TOPIC)

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
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    expected_message = UDPMessage(code=codes.HANDSHAKE, topic=Handshake.AUTHENTICATION_REQUIRED_TOPIC)

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
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

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
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

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
    allowed_authentication_method = ["password"]
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_to_derive.decode("utf8")}
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_client)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    expected_id = codes.HANDSHAKE
    expected_topic = Handshake.AUTHENTICATION_TOPIC

    # When
    result = client.next_message()
    payload = client._decrypt(result.payload)
    payload = json.loads(bytes.decode(payload, "utf8"))
    password = payload[Handshake.AUTH_METHOD_INFO_KEY]["password"]

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic

    assert password == password_to_derive.decode('utf8')


def test_next_message_return_connection_approved_message_when_connection_step_6_and_role_is_server_and_password_ok():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_to_derive.decode("utf8")}
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_client)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())

    expected_id = codes.HANDSHAKE
    expected_topic = Handshake.CONNECTION_APPROVED_TOPIC

    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic


def test_next_message_return_connection_failed_msg_when_connection_step_6_and_role_is_client_and_password_incorrect():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test"
    password_client = "incorrect"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_client}
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_client)

    expected_id = codes.HANDSHAKE
    expected_topic = Handshake.CONNECTION_FAILED_TOPIC

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
    role = Handshake.CLIENT
    client = Handshake(role=role)
    expected_message = UDPMessage(code=codes.HANDSHAKE, topic=Handshake.CONNECTION_REQUEST_TOPIC)
    connection_request_message = client.next_message()

    # When
    result = json.loads(bytes.decode(connection_request_message.payload, "utf8"))

    # Then
    assert Handshake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME in result.keys()
    assert type(result[Handshake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME]) is list
    assert len(result[Handshake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME]) > 0
    assert result[Handshake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME][0] == "alpha"
    assert result[Handshake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME] == Handshake.PROTOCOL_VERSIONS_AVAILABLE


def test_authentication_required_message_contain_a_list_of_authentication_methods_available():
    # Given
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = Handshake.AUTHENTICATION_METHODS_AVAILABLE
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_to_derive}
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=["password"],
                       authentication_information=authentication_information_client)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    authentication_required_message = server.next_message()

    # When
    result = json.loads(bytes.decode(authentication_required_message.payload, "utf8"))

    # Then
    assert Handshake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME in result.keys()
    assert type(result[Handshake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME]) is list
    assert len(result[Handshake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME]) > 0
    assert result[Handshake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME] == Handshake.AUTHENTICATION_METHODS_AVAILABLE


def test_get_status_return_incomplete_when_role_is_client_and_handshake_process_not_started():
    # Given
    role = Handshake.CLIENT
    client = Handshake(role=role)

    # When
    result = client.get_status()

    # Then
    assert result == Handshake.CONNECTION_STATUS_INCOMPLETE


def test_get_status_return_complete_when_and_handshake_was_successful_without_authentication():
    # Given
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    result_client = client.get_status()
    result_server = server.get_status()

    # Then
    assert result_client == Handshake.CONNECTION_STATUS_APPROVED
    assert result_server == Handshake.CONNECTION_STATUS_APPROVED


def test_get_status_return_failed_when_authentication_is_incorrect():
    # Given
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    password_client = "incorrect"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_methods = ["password"]
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_client}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods)
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, authentication_information=authentication_information_server,
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
    assert result_client == Handshake.CONNECTION_STATUS_FAILED
    assert result_server == Handshake.CONNECTION_STATUS_FAILED


def test_get_status_return_approved_when_authentication_is_correct():
    # Given
    allowed_authentication_methods = ["password"]
    password_to_derive = b"test"
    password_salt = os.urandom(16)
    password_client = "test"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, authentication_information=authentication_information_server,
                       allowed_authentication_methods=allowed_authentication_methods)
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_client}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
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
    assert result_client == Handshake.CONNECTION_STATUS_APPROVED
    assert result_server == Handshake.CONNECTION_STATUS_APPROVED


def test_server_key_share_message_contain_selected_protocol_version_which_is_the_latest_available():
    # Given
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert Handshake.SELECTED_PROTOCOL_VERSION_KEY_NAME in result.keys()
    assert result[Handshake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == Handshake.PROTOCOL_VERSIONS_AVAILABLE[-1]


def test_allowed_protocols_versions_can_be_defined_to_only_1_dot_0_when_handshake_is_created():
    # Given
    allowed_protocol_versions = ['1.0']
    server = Handshake(role=Handshake.SERVER, allowed_protocol_versions=allowed_protocol_versions)

    # When
    result = server.get_allowed_protocol_versions()

    # Then
    assert result == allowed_protocol_versions


def test_allowed_protocols_versions_can_be_defined_to_only_alpha_when_handshake_is_created():
    # Given
    allowed_protocol_versions = ['alpha']
    server = Handshake(role=Handshake.SERVER, allowed_protocol_versions=allowed_protocol_versions)

    # When
    result = server.get_allowed_protocol_versions()

    # Then
    assert result == allowed_protocol_versions


def test_allowed_protocols_versions_default_value_is_all_available_protocol_versions():
    # Given
    server = Handshake(role=Handshake.SERVER)

    # When
    result = server.get_allowed_protocol_versions()

    # Then
    assert result == Handshake.PROTOCOL_VERSIONS_AVAILABLE


def test_handshake_raise_value_error_if_a_version_label_provided_does_not_exist():
    # Given
    allowed_protocol_versions = ['alpha', 'test_version_that_does_not_exist']

    # When

    # Then
    with pytest.raises(ValueError):
        server = Handshake(role=Handshake.SERVER, allowed_protocol_versions=allowed_protocol_versions)


def test_server_key_share_message_inform_selected_protocol_is_alpha_if_it_is_the_only_available_for_client():
    # Given
    allowed_protocol_versions = ['alpha']
    expected_result = "alpha"
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT, allowed_protocol_versions=allowed_protocol_versions)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert result[Handshake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == expected_result


def test_server_key_share_message_inform_selected_protocol_is_1_dot_0_if_clients_allowed_protocol_not_sorted():
    # Given
    allowed_protocol_versions = ['1.0', 'alpha']
    expected_result = "1.0"
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT, allowed_protocol_versions=allowed_protocol_versions)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert result[Handshake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == expected_result


def test_server_key_share_message_inform_selected_protocol_is_alpha_if_it_is_the_only_available_for_server():
    # Given
    allowed_protocol_versions = ['alpha']
    expected_result = "alpha"
    server = Handshake(role=Handshake.SERVER, allowed_protocol_versions=allowed_protocol_versions)
    client = Handshake(role=Handshake.CLIENT)

    server.add_message(client.next_message())
    server_key_share_message = server.next_message()

    # When
    result = json.loads(bytes.decode(server_key_share_message.payload, "utf8"))

    # Then
    assert result[Handshake.SELECTED_PROTOCOL_VERSION_KEY_NAME] == expected_result


def test_connection_fail_if_server_and_client_have_not_a_common_protocol_version():
    # Given
    allowed_protocol_versions_client = ['alpha']
    allowed_protocol_versions_server = ['1.0']
    server = Handshake(role=Handshake.SERVER, allowed_protocol_versions=allowed_protocol_versions_server)
    client = Handshake(role=Handshake.CLIENT, allowed_protocol_versions=allowed_protocol_versions_client)

    server.add_message(client.next_message())

    # When
    connection_failed_message = server.next_message()
    client.add_message(connection_failed_message)

    # Then
    assert server.get_status() == Handshake.CONNECTION_STATUS_FAILED
    assert client.get_status() == Handshake.CONNECTION_STATUS_FAILED
    assert int.from_bytes(connection_failed_message.topic, 'little') == Handshake.CONNECTION_FAILED_TOPIC


def test_connection_fail_if_abort_is_called_on_server_after_a_connection_request():
    # Given

    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)

    server.add_message(client.next_message())

    # When
    server.abort()
    connection_failed_message = server.next_message()
    client.add_message(connection_failed_message)

    # Then
    assert server.get_status() == Handshake.CONNECTION_STATUS_FAILED
    assert client.get_status() == Handshake.CONNECTION_STATUS_FAILED
    assert int.from_bytes(connection_failed_message.topic, 'little') == Handshake.CONNECTION_FAILED_TOPIC


def test_connection_fail_if_abort_is_called_on_client_after_a_connection_request():
    # Given
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)

    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    client.abort()
    connection_failed_message = client.next_message()
    server.add_message(connection_failed_message)

    # Then
    assert server.get_status() == Handshake.CONNECTION_STATUS_FAILED
    assert client.get_status() == Handshake.CONNECTION_STATUS_FAILED
    assert int.from_bytes(connection_failed_message.topic, 'little') == Handshake.CONNECTION_FAILED_TOPIC


def test_time_creation_return_handshake_time_of_creation():
    # Given
    time_test_start = time.time()
    time.sleep(.001)
    client = Handshake(role=Handshake.CLIENT)
    time.sleep(.001)

    # When
    result = client.time_creation()

    # Then
    assert time_test_start < client.time_creation() < time.time()


def test_no_authentication_is_required_when_no_allowed_authentication_method_provided():
    # Given
    allowed_authentication_method = []
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == Handshake.CONNECTION_APPROVED_TOPIC


def test_allowed_authentication_methods_default_value_is_no_authentication():
    # Given
    server = Handshake(role=Handshake.SERVER)
    client = Handshake(role=Handshake.CLIENT)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == Handshake.CONNECTION_APPROVED_TOPIC


def test_authentication_is_required_if_password_is_provided_as_authentication_method():
    # Given
    allowed_authentication_methods = ["password"]
    password_salt = os.urandom(16)
    password_to_derive = b"test"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_methods,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_methods)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    # When
    result = server.next_message()

    # Then
    assert int.from_bytes(result.msg_id, 'little') == codes.HANDSHAKE
    assert int.from_bytes(result.topic, 'little') == Handshake.AUTHENTICATION_REQUIRED_TOPIC


def test_handshake_raise_value_error_if_a_authentication_method_provided_does_not_exist():
    # Given
    allowed_authentication_methods = ['password', 'authentication_method_that_does_not_exist']

    # When

    # Then
    with pytest.raises(ValueError):
        server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_methods)


def test_authentication_message_select_password_method_if_it_is_the_only_authentication_method_for_both_instances():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test_password"
    allowed_authentication_methods = ["password"]
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_to_derive.decode("utf8")}
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, authentication_information=authentication_information_server,
                       allowed_authentication_methods=allowed_authentication_methods)
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    authentication_message = client.next_message()

    # When
    payload = client._decrypt(authentication_message.payload)
    result = json.loads(bytes.decode(payload, "utf8"))

    # Then
    assert Handshake.SELECTED_AUTHENTICATION_METHOD_KEY_NAME in result.keys()
    assert result[Handshake.SELECTED_AUTHENTICATION_METHOD_KEY_NAME] == "password"


def test_authentication_message_select_custom_method_if_it_is_the_only_authentication_method_for_both_instances():
    # Given
    allowed_authentication_methods = ["custom"]
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_methods)
    authentication_information_client = {}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    authentication_message = client.next_message()

    # When
    payload = client._decrypt(authentication_message.payload)
    result = json.loads(bytes.decode(payload, "utf8"))

    # Then
    assert result[Handshake.SELECTED_AUTHENTICATION_METHOD_KEY_NAME] == "custom"


def test_client_next_message_is_connection_failed_if_no_authentication_method_available_after_auth_request():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test_password"
    allowed_authentication_methods_server = ["password"]
    allowed_authentication_methods_client = []
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_to_derive}
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods_client)
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, authentication_information=authentication_information_server,
                       allowed_authentication_methods=allowed_authentication_methods_server)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    connection_failed_message = client.next_message()

    # Then
    assert int.from_bytes(connection_failed_message.topic, 'little') == Handshake.CONNECTION_FAILED_TOPIC


def test_client_next_message_is_connection_failed_if_no_common_authentication_method_auth_request():
    # Given
    allowed_authentication_methods_server = ["password"]
    allowed_authentication_methods_client = ["custom"]
    password_salt = os.urandom(16)
    password_to_derive = b"test_password"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_to_derive}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods_client)
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, authentication_information=authentication_information_server,
                       allowed_authentication_methods=allowed_authentication_methods_server)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    # When
    connection_failed_message = client.next_message()

    # Then
    assert int.from_bytes(connection_failed_message.topic, 'little') == Handshake.CONNECTION_FAILED_TOPIC


def test_authentication_message_contain_random_bits_of_correct_length():
    # Given
    password_salt = os.urandom(16)
    password_to_derive = b"test"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)
    allowed_authentication_method = ["password"]
    authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_to_derive.decode("utf8")}
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_client)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())

    expected_id = codes.HANDSHAKE
    expected_topic = Handshake.AUTHENTICATION_TOPIC

    # When
    result = client.next_message()
    payload = client._decrypt(result.payload)
    payload = json.loads(bytes.decode(payload, "utf8"))

    # Then
    assert int.from_bytes(result.msg_id, 'little') == expected_id
    assert int.from_bytes(result.topic, 'little') == expected_topic
    assert Handshake.AUTHENTICATION_RANDOM_BITS_KEY in payload.keys()
    assert len(base64.b64decode(payload[Handshake.AUTHENTICATION_RANDOM_BITS_KEY])) == Handshake.RANDOM_BITS_LENGTH


def test_client_status_is_waiting_approval_when_authentication_method_is_custom():
    # Given
    expected_status = Handshake.CONNECTION_STATUS_WAIT_APPROVAL
    allowed_authentication_methods_client = ["custom"]
    allowed_authentication_methods_server = ["custom"]
    authentication_information_client = {}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods_client)
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_methods_server)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())

    # When
    status = server.get_status()

    # Then
    assert status == expected_status


def test_client_status_is_failed_when_authentication_method_is_custom_and_disapprove_is_called():
    # Given
    expected_status = Handshake.CONNECTION_STATUS_FAILED
    allowed_authentication_methods_client = ["custom"]
    allowed_authentication_methods_server = ["custom"]
    authentication_information_client = {}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods_client)
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_methods_server)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())

    # When
    server.disapprove()
    status = server.get_status()

    # Then
    assert status == expected_status


def test_get_authentication_information_return_given_authentication_information_when_custom_method_is_used():
    # Given
    allowed_authentication_methods_client = ["custom"]
    allowed_authentication_methods_server = ["custom"]
    authentication_information_client = {"test": "test"}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods_client)
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_methods_server)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())

    # When
    info = server.get_authentication_information()

    # Then
    assert info == authentication_information_client


def test_client_status_is_approved_when_authentication_method_is_custom_and_approve_is_called():
    # Given
    expected_status = Handshake.CONNECTION_STATUS_APPROVED
    allowed_authentication_methods_client = ["custom"]
    allowed_authentication_methods_server = ["custom"]
    authentication_information_client = {}
    client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                       allowed_authentication_methods=allowed_authentication_methods_client)
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_methods_server)

    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())
    client.add_message(server.next_message())
    server.add_message(client.next_message())

    # When
    server.approve()
    client.add_message(server.next_message())
    status_server = server.get_status()
    status_client = client.get_status()

    # Then
    assert status_server == expected_status
    assert status_client == expected_status


def test_next_message_return_connection_failed_msg_when_connection_step_6_and_role_is_client_and_auth_info_is_none():
    # Given
    password_salt = os.urandom(16)
    password = b"incorrect"
    derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password)
    allowed_authentication_method = ["password"]
    expected_topic = Handshake.CONNECTION_FAILED_TOPIC
    expected_id = codes.HANDSHAKE
    authentication_information_server = {
        "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                     Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
    server = Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_server)
    authentication_information_client = None
    client = Handshake(role=Handshake.CLIENT, allowed_authentication_methods=allowed_authentication_method,
                       authentication_information=authentication_information_client)

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


def test_new_server_raise_error_when_password_auth_is_allowed_but_no_auth_info_are_given():
    # Given
    allowed_authentication_method = ["password"]

    # When

    # Then
    with pytest.raises(AttributeError):
        Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method)


def test_new_server_raise_error_when_password_auth_is_allowed_but_incomplete_auth_info_are_given():
    # Given
    allowed_authentication_method = ["password"]
    auth_info = {"password": {}}

    # When

    # Then
    with pytest.raises(AttributeError):
        Handshake(role=Handshake.SERVER, allowed_authentication_methods=allowed_authentication_method,
                  authentication_information=auth_info)

# python -m pytest -s hermes/security/tests/test_Handshake.py -vv
