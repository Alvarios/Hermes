# -*- coding: utf-8 -*-
"""Implementation of a handshake for secure secret exchanges and authentication.

    Copyright (C) 2020  Clement Dulouard

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If your software can interact with users remotely through a computer
network, you should also make sure that it provides a way for users to
get its source.  For example, if your program is a web application, its
interface could display a "Source" link that leads users to an archive
of the code.  There are many ways you could offer source, and different
solutions will be better for different programs; see section 13 for the
specific requirements.

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU AGPL, see
<https://www.gnu.org/licenses/>.
"""

from typing import Optional, Union, NoReturn, List
from hermes.messages.UDPMessage import UDPMessage
from cryptography.hazmat.primitives import serialization
import hermes.messages.codes as codes
from cryptography.hazmat.primitives.asymmetric import ec
from hermes.security.utils import verify_password_scrypt, derive_key_hkdf
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import json
import time
import base64


class Handshake:
    """A class that can be used for handshake between a client and a server. The main job is to
    provide a way to create a shared key in a secure way using Elliptic Curve Diffie-Hellman (ECDH) to
    create a secure communication tunnel between client and server.

    An additional layer of security can be added by requiring client authentication before validating
    connection.

        The communication between client and server work as following :

            Step 1 : Client ask server's to connect.
            Step 2 : Server send its public key to client.
            Step 3 Client send it's public key to server.

            if no authentication required :
                Step 4 : Server send connection approved message to client and both can used the shared key.
                for secure connection

            if authentication is required :
                Step 4 : Server inform client the authentication is required.
                Step 5 : Client send authentication information to server.
                Step 6 : Server send connection approved to client if information is correct else it send
                        connection failed message.

        Constants :
            SERVER : Value that tell the Handshake role is server.
            CLIENT : Value that tell the Handshake role is client.

            PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME : The key name for protocols available used for metadata.
            SELECTED_PROTOCOL_VERSION_KEY_NAME : The key name used to specify which protocol will be used for the
            handshake in the metadata.
            SERVER_PUBLIC_KEY_KEY_NAME : The key name used for server public key.
            SERVER_PUBLIC_KEY_KEY_NAME : The key name used for client public key.
            AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME : The key name for authentication method available used
            for metadata.
            SELECTED_AUTHENTICATION_METHOD_KEY_NAME : The key name used to specify which authentication method will be
             used for the handshake in the metadata.

            PROTOCOL_VERSIONS_AVAILABLE : A list of protocol version available for the handshake. The newest version of
            the protocol will be used.
            AUTHENTICATION_METHODS_AVAILABLE : A list of authentication methods available for the handshake's
            authentication step. The client must use a method in this list to do authentication or send connection
            failed message.

            AUTHENTICATION_RANDOM_BITS_KEY : The key used to add random bits during authentication
            (for security reasons).

            PASSWORD_AUTH_METHOD_PASSWORD_KEY : The key name used in password authentication method to provide password.
            PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY : The key name used in password authentication method to provide
             derived password.
            PASSWORD_AUTH_METHOD_SALT_KEY : The key name used in password authentication method to salt.

            CONNECTION_FAILED_TOPIC : UDPMessage topic used to inform connection failed.
            CONNECTION_REQUEST_TOPIC : UDPMessage topic used to inform a client want to create a connection.
            SERVER_KEY_SHARE_TOPIC : UDPMessage topic used to inform the server has send its public key.
            CLIENT_KEY_SHARE_TOPIC : UDPMessage topic used to inform the client has send its public key.
            CONNECTION_APPROVED_TOPIC : UDPMessage topic used to inform the connection has been approved by the server.
            AUTHENTICATION_REQUIRED_TOPIC : UDPMessage topic used to inform the authentication is required to approve
                                            the connection.
            AUTHENTICATION_TOPIC : UDPMessage topic used to inform the message contain the authentication information..

            NONCE_LENGTH : The length of nonce used for encryption (in bits).
            RANDOM_BYTES_LENGTH : The length of random bytes added to authentication messages (in bits).

            CONNECTION_STATUS_INCOMPLETE : The label used for incomplete handshake status.
            CONNECTION_STATUS_APPROVED : The label used for approved handshake status.
            CONNECTION_STATUS_FAILED : The label used for failed handshake status.

        Attributes :
            role : The role of the current Handshake (client or server).
            _derived_password : Only required for role server. The derived password used for authentication (if set
                                to None no authentication is required)
            _password_salt : Only required for role server. The salt used for key derivation corresponding to
                            _derived_password as bytes.
            _last_step : Stores the last validated step of the handshake.
            _peer_public_key : Stores the peer public key when it has been received.
            _private_key : Stores the ephemeral private key used for handshake.
            _symmetric_encryption_key : The key used for symmetric encryption (needed for secure authentication).
            _authentication_approved : Boolean that is set to True if the authentication is successful.
            _connection_status : Store the status of the handshake.
            _allowed_protocol_versions : Store a list of allowed protocol versions.
            _client_protocol_versions : A list of all client's protocol versions available.
            _allowed_authentication_method : Store a list of allowed authentication method.
            _server_authentication_method : A list of all servers's authentication methods available.
            _time_creation : The creation time of the instance.
            _selected_authentication_method : Store the selected authentication method when role is client.
            _custom_authentication_info : Store the custom authentication info sent by client.
    """

    SERVER = "server"
    CLIENT = "client"

    PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME = "protocols_available"
    SELECTED_PROTOCOL_VERSION_KEY_NAME = "selected_protocol_version"
    SERVER_PUBLIC_KEY_KEY_NAME = "server_public_key"
    CLIENT_PUBLIC_KEY_KEY_NAME = "client_public_key"
    AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME = "authentication_methods_available"
    SELECTED_AUTHENTICATION_METHOD_KEY_NAME = "selected_authentication_method"

    PROTOCOL_VERSIONS_AVAILABLE = ["alpha", "1.0"]
    AUTHENTICATION_METHODS_AVAILABLE = ["password", "custom"]

    AUTHENTICATION_RANDOM_BITS_KEY = "random_bits"

    PASSWORD_AUTH_METHOD_PASSWORD_KEY = "password"
    PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY = "derived_password"
    PASSWORD_AUTH_METHOD_SALT_KEY = "salt"

    CUSTOM_AUTH_METHOD_INFO_KEY = "authentication_info"

    CONNECTION_FAILED_TOPIC = 0
    CONNECTION_REQUEST_TOPIC = 1
    SERVER_KEY_SHARE_TOPIC = 2
    CLIENT_KEY_SHARE_TOPIC = 3
    CONNECTION_APPROVED_TOPIC = 4
    AUTHENTICATION_REQUIRED_TOPIC = 5
    AUTHENTICATION_TOPIC = 6

    NONCE_LENGTH = 12
    RANDOM_BITS_LENGTH = 32

    CONNECTION_STATUS_INCOMPLETE = "incomplete"
    CONNECTION_STATUS_APPROVED = "approved"
    CONNECTION_STATUS_FAILED = "failed"
    CONNECTION_STATUS_WAIT_APPROVAL = "wait_approval"

    def __init__(self, role: Optional[str] = SERVER, authentication_information: Optional[Union[None, dict]] = None,
                 allowed_protocol_versions: Optional[Union[None, list]] = None,
                 allowed_authentication_methods: Optional[Union[None, list]] = None) -> None:
        """Create a new Handshake object with given parameter.

        :param role: The role of the current Handshake (client or server).
        :param authentication_information :  Only required for role client. The information used by client
        for authentication.
        :param allowed_protocol_versions: A list of allowed protocol versions. All elements in the list must be
        in Handshake.PROTOCOL_VERSIONS_AVAILABLE.
        :param allowed_protocol_versions: A list of allowed authentication method. All elements in the list must be
        in Handshake.PROTOCOL_VERSIONS_AVAILABLE.
        """
        # TODO : manage error when received message is corrupted.
        # TODO : Manage error when received message format is incorrect.
        self.role = role
        self._derived_password = None
        self._password_salt = None
        if authentication_information is not None and self.role == Handshake.SERVER:
            if Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY in authentication_information["password"].keys():
                self._derived_password = authentication_information["password"][
                    Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY]
            if Handshake.PASSWORD_AUTH_METHOD_SALT_KEY in authentication_information["password"].keys():
                self._password_salt = authentication_information["password"][Handshake.PASSWORD_AUTH_METHOD_SALT_KEY]
        self._last_step = 0
        self._peer_public_key = None
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        self._symmetric_encryption_key = None
        self._authentication_information = authentication_information
        # TODO : Check when authentication info is None
        self._authentication_approved = False
        self._connection_status = Handshake.CONNECTION_STATUS_INCOMPLETE
        if allowed_protocol_versions is None:
            allowed_protocol_versions = Handshake.PROTOCOL_VERSIONS_AVAILABLE
        if not all(i in Handshake.PROTOCOL_VERSIONS_AVAILABLE for i in allowed_protocol_versions):
            raise ValueError("All allowed protocol versions must be in Handshake.PROTOCOL_VERSIONS_AVAILABLE.")
        self._allowed_protocol_versions = [version for version in Handshake.PROTOCOL_VERSIONS_AVAILABLE if
                                           version in allowed_protocol_versions]
        self._client_protocol_versions = None
        if allowed_authentication_methods is None:
            allowed_authentication_methods = []
        if not all(i in Handshake.AUTHENTICATION_METHODS_AVAILABLE for i in allowed_authentication_methods):
            raise ValueError(
                "All allowed authentication methods must be in Handshake.AUTHENTICATION_METHODS_AVAILABLE.")
        self._allowed_authentication_methods = allowed_authentication_methods
        self._server_authentication_method = None
        self._time_creation = time.time()
        if role is Handshake.CLIENT and len(allowed_authentication_methods) >= 2:
            raise NotImplementedError("Multiple authentication method for client is not supported yet.")
        self._selected_authentication_method: Union[None, str] = None
        self._custom_authentication_info = {}

    def _verify_password(self, password_to_verify: bytes) -> bool:
        """Check if the input password correspond to the instance derived password and salt.

        :param password_to_verify: The password to verify as bytes.

        :return: True if no derived password has been set or if the input is verified, else False.
        """
        if self._derived_password is None:
            return True
        return verify_password_scrypt(password_to_verify=password_to_verify, derived_password=self._derived_password,
                                      password_salt=self._password_salt)

    def next_message(self) -> Union[None, UDPMessage]:
        """Return the next message to send to remote host based on current instance state.

        :return next_message: A UDPMessage to send to remote host to continue handshake process.
        """
        if self._connection_status == Handshake.CONNECTION_STATUS_FAILED:
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CONNECTION_FAILED_TOPIC)

        if self.role == Handshake.CLIENT:
            return self._next_message_client()

        if self.role == Handshake.SERVER:
            return self._next_message_server()

    def _next_message_client(self) -> Union[None, UDPMessage]:
        """Return the next message if instance role is client.

        :return next_message: A UDPMessage to send to remote host to continue handshake process.
        """
        if self._last_step == Handshake.SERVER_KEY_SHARE_TOPIC:
            public_bytes = bytes.decode(
                self._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.
                                                            SubjectPublicKeyInfo), "ascii")
            payload = str.encode(
                json.dumps({Handshake.CLIENT_PUBLIC_KEY_KEY_NAME: public_bytes}), "utf8")
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CLIENT_KEY_SHARE_TOPIC,
                              payload=payload)

        if self._last_step == Handshake.AUTHENTICATION_REQUIRED_TOPIC:
            if self._selected_authentication_method is None:
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CONNECTION_FAILED_TOPIC)
            # TODO : Use base 64 instead of str encode when possible.
            payload = b""
            if self._selected_authentication_method == "password":
                authentication_information = base64.b64encode(self._encrypt(
                    self._authentication_information[Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY])).decode("ascii")
                random_bits = base64.b64encode(os.urandom(Handshake.RANDOM_BITS_LENGTH)).decode("ascii")
                payload = str.encode(json.dumps(
                    {Handshake.SELECTED_AUTHENTICATION_METHOD_KEY_NAME: self._selected_authentication_method,
                     Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY:
                         authentication_information,
                     Handshake.AUTHENTICATION_RANDOM_BITS_KEY: random_bits}), "utf8")
            if self._selected_authentication_method == "custom":
                payload = str.encode(json.dumps(
                    {Handshake.SELECTED_AUTHENTICATION_METHOD_KEY_NAME: self._selected_authentication_method,
                     Handshake.CUSTOM_AUTH_METHOD_INFO_KEY: self._authentication_information}), "utf8")
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.AUTHENTICATION_TOPIC, payload=payload)

        payload = str.encode(
            json.dumps({Handshake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME: self._allowed_protocol_versions}),
            "utf8")
        return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CONNECTION_REQUEST_TOPIC, payload=payload)

    def _next_message_server(self) -> Union[None, UDPMessage]:
        """Return the next message if instance role is server.

        :return next_message: A UDPMessage to send to remote host to continue handshake process.
        """
        if self._last_step == Handshake.CONNECTION_REQUEST_TOPIC:
            public_bytes = bytes.decode(
                self._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PublicFormat.
                                                            SubjectPublicKeyInfo), "ascii")
            protocol_version = ""
            for version in self._client_protocol_versions:
                if version in self._allowed_protocol_versions:
                    protocol_version = version
            if protocol_version == "":
                self._connection_status = Handshake.CONNECTION_STATUS_FAILED
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CONNECTION_FAILED_TOPIC)
            payload = str.encode(
                json.dumps({Handshake.SELECTED_PROTOCOL_VERSION_KEY_NAME: protocol_version,
                            Handshake.SERVER_PUBLIC_KEY_KEY_NAME: public_bytes}),
                "utf8")
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.SERVER_KEY_SHARE_TOPIC, payload=payload)

        if self._last_step == Handshake.CLIENT_KEY_SHARE_TOPIC and len(self._allowed_authentication_methods) == 0:
            self._connection_status = Handshake.CONNECTION_STATUS_APPROVED
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CONNECTION_APPROVED_TOPIC)

        # If authentication is required
        if self._last_step == Handshake.CLIENT_KEY_SHARE_TOPIC and len(self._allowed_authentication_methods) != 0:
            payload = str.encode(json.dumps(
                {Handshake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME: self._allowed_authentication_methods}),
                "utf8")
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.AUTHENTICATION_REQUIRED_TOPIC,
                              payload=payload)

        if self._last_step == Handshake.AUTHENTICATION_TOPIC and (
                self._derived_password is not None or self._selected_authentication_method != "password"):
            if self._authentication_approved:
                self._connection_status = Handshake.CONNECTION_STATUS_APPROVED
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CONNECTION_APPROVED_TOPIC)
            self._connection_status = Handshake.CONNECTION_STATUS_FAILED
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=Handshake.CONNECTION_FAILED_TOPIC)
        return None

    def add_message(self, msg: UDPMessage) -> NoReturn:
        """Handle given message and change Handshake state if needed.

        :param msg: The UDPMessage to read.
        """
        msg_id = int.from_bytes(msg.msg_id, 'little')
        msg_topic = int.from_bytes(msg.topic, 'little')
        if msg_id != codes.HANDSHAKE:
            return

        if msg_topic == Handshake.CONNECTION_FAILED_TOPIC:
            self._connection_status = Handshake.CONNECTION_STATUS_FAILED

        if msg_topic == Handshake.CONNECTION_REQUEST_TOPIC:
            payload = json.loads(bytes.decode(msg.payload, "utf8"))
            self._client_protocol_versions = payload[Handshake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME]
            self._last_step = msg_topic

        if msg_topic == Handshake.SERVER_KEY_SHARE_TOPIC:
            self._last_step = msg_topic
            payload = json.loads(bytes.decode(msg.payload, "utf8"))
            self._peer_public_key = serialization.load_pem_public_key(
                str.encode(payload[Handshake.SERVER_PUBLIC_KEY_KEY_NAME], 'ascii'))
            self._symmetric_encryption_key = derive_key_hkdf(key=self.get_shared_key(), length=32)

        if msg_topic == Handshake.CLIENT_KEY_SHARE_TOPIC:
            self._last_step = msg_topic
            payload = json.loads(bytes.decode(msg.payload, "utf8"))
            self._peer_public_key = serialization.load_pem_public_key(
                str.encode(payload[Handshake.CLIENT_PUBLIC_KEY_KEY_NAME], 'ascii'))
            self._symmetric_encryption_key = derive_key_hkdf(key=self.get_shared_key(), length=32)

        if msg_topic == Handshake.AUTHENTICATION_REQUIRED_TOPIC:
            payload = json.loads(bytes.decode(msg.payload, "utf8"))
            self._server_authentication_method = payload[Handshake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME]
            if len(self._allowed_authentication_methods) > 0 and self._allowed_authentication_methods[0] \
                    in self._server_authentication_method:
                self._selected_authentication_method = self._allowed_authentication_methods[0]
            self._last_step = msg_topic

        if msg_topic == Handshake.AUTHENTICATION_TOPIC:
            self._last_step = msg_topic
            payload = json.loads(bytes.decode(msg.payload, "utf8"))
            if payload[Handshake.SELECTED_AUTHENTICATION_METHOD_KEY_NAME] == "custom":
                self._connection_status = Handshake.CONNECTION_STATUS_WAIT_APPROVAL
                self._custom_authentication_info = payload[Handshake.CUSTOM_AUTH_METHOD_INFO_KEY]
                return
            password = base64.b64decode(str.encode(payload[Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY], 'ascii'))
            self._authentication_approved = self._verify_password(self._decrypt(password))

        if msg_topic == Handshake.CONNECTION_APPROVED_TOPIC:
            self._connection_status = Handshake.CONNECTION_STATUS_APPROVED

    def get_shared_key(self) -> bytes:
        """Return the resulting key after Diffie-Hellman key exchange.

        :return: The shared key generated using ECDH as bytes.
        """
        return self._private_key.exchange(ec.ECDH(), self._peer_public_key)

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt input with ChaCha20Poly1305 algorithm using _symmetric_encryption_key as key.

        :param data: The data to encrypt.

        :return: Encrypted data as bytes.
        """
        chacha = ChaCha20Poly1305(self._symmetric_encryption_key)
        nonce = os.urandom(Handshake.NONCE_LENGTH)
        return nonce + chacha.encrypt(nonce, data, b"")

    def _decrypt(self, encrypted_message: bytes) -> bytes:
        """Decrypt data encrypted with _encrypt.

        :param encrypted_message: The data encrypted with _encrypt that need to be decrypted.

        :return: The decrypted data as bytes.
        """
        chacha = ChaCha20Poly1305(self._symmetric_encryption_key)
        return chacha.decrypt(encrypted_message[:Handshake.NONCE_LENGTH], encrypted_message[Handshake.NONCE_LENGTH:],
                              b"")

    def get_status(self) -> str:
        """Return the current status of the Handshake.

        :return: The current status of the instance.
        """
        return self._connection_status

    def get_allowed_protocol_versions(self) -> List[str]:
        """Return the list of available protocol versions for this instance.

        :return: The list of available protocol versions for this instance.
        """
        return self._allowed_protocol_versions

    def abort(self) -> NoReturn:
        """Set the connection status to failed so next_message return connection failed message."""
        self._connection_status = Handshake.CONNECTION_STATUS_FAILED

    def time_creation(self) -> float:
        """Return the time of creation of the instance.

        :return: The time of creation of the instance.
        """
        return self._time_creation

    def disapprove(self) -> NoReturn:
        """Disapprove connection for custom authentication method."""
        self._connection_status = Handshake.CONNECTION_STATUS_FAILED

    def approve(self):
        """"Approve connection for custom authentication method."""
        self._connection_status = Handshake.CONNECTION_STATUS_INCOMPLETE
        self._authentication_approved = True

    def get_authentication_information(self):
        return self._custom_authentication_info
