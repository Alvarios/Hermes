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


class HandShake:
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
            SERVER : Value that tell the HandShake role is server.
            CLIENT : Value that tell the HandShake role is client.

            PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME : The key name for protocols available used for metadata.
            SELECTED_PROTOCOL_VERSION_KEY_NAME : The key name used to specify which protocol will be used for the
            handshake in the metadata.
            SERVER_PUBLIC_KEY_KEY_NAME : The key name used for server public key.
            AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME : The key name for authentication method available used
            for metadata.
            SELECTED_AUTHENTICATION_METHOD_KEY_NAME : The key name used to specify which authentication method will be
             used for the handshake in the metadata.

            PROTOCOL_VERSIONS_AVAILABLE : A list of protocol version available for the handshake. The newest version of protocol
            available for both device will be used for the handshake.
            AUTHENTICATION_METHODS_AVAILABLE : A list of authentication methods available for the handshake's
            authentication step. The client must use a method in this list to do authentication or send connection
            failed message.

            CONNECTION_FAILED_TOPIC : UDPMessage topic used to inform connection failed.
            CONNECTION_REQUEST_TOPIC : UDPMessage topic used to inform a client want to create a connection.
            SERVER_KEY_SHARE_TOPIC : UDPMessage topic used to inform the server has send its public key.
            CLIENT_KEY_SHARE_TOPIC : UDPMessage topic used to inform the client has send its public key.
            CONNECTION_APPROVED_TOPIC : UDPMessage topic used to inform the connection has been approved by the server.
            AUTHENTICATION_REQUIRED_TOPIC : UDPMessage topic used to inform the authentication is required to approve
                                            the connection.
            AUTHENTICATION_TOPIC : UDPMessage topic used to inform the message contain the authentication information..
            NONCE_LENGTH : The length of nonce used for encryption.

            CONNECTION_STATUS_INCOMPLETE : The label used for incomplete handshake status.
            CONNECTION_STATUS_APPROVED : The label used for approved handshake status.
            CONNECTION_STATUS_FAILED : The label used for failed handshake status.

        Attributes :
            role : The role of the current HandShake (client or server).
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
    """

    SERVER = "server"
    CLIENT = "client"

    PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME = "protocols_available"
    SELECTED_PROTOCOL_VERSION_KEY_NAME = "selected_protocol_version"
    SERVER_PUBLIC_KEY_KEY_NAME = "server_public_key"
    AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME = "authentication_methods_available"
    SELECTED_AUTHENTICATION_METHOD_KEY_NAME = "selected_authentication_method"

    PROTOCOL_VERSIONS_AVAILABLE = ["alpha", "1.0"]
    # TODO: Add a method to chose which authentication methods the HandShake instance will use.
    AUTHENTICATION_METHODS_AVAILABLE = ["password"]

    CONNECTION_FAILED_TOPIC = 0
    CONNECTION_REQUEST_TOPIC = 1
    SERVER_KEY_SHARE_TOPIC = 2
    CLIENT_KEY_SHARE_TOPIC = 3
    CONNECTION_APPROVED_TOPIC = 4
    AUTHENTICATION_REQUIRED_TOPIC = 5
    AUTHENTICATION_TOPIC = 6

    NONCE_LENGTH = 12

    CONNECTION_STATUS_INCOMPLETE = "incomplete"
    CONNECTION_STATUS_APPROVED = "approved"
    CONNECTION_STATUS_FAILED = "failed"

    def __init__(self, role: Optional[str] = SERVER, derived_password: Optional[Union[None, bytes]] = None,
                 password_salt: Optional[Union[None, bytes]] = None, authentication_information=None,
                 allowed_protocol_versions: Optional[Union[None, list]] = None) -> None:
        """Create a new HandShake object with given parameter.

        :param role: The role of the current HandShake (client or server).
        :param derived_password: Only required for role server. The derived password to use for password verification as
         bytes. If None no authentication will be required during the handshake.
        :param password_salt : Only required for role server. The salt used for key derivation corresponding to
        derived_password as bytes.
        :param authentication_information :  Only required for role client. The information used by client
        for authentication.
        """
        # TODO : manage error when received message is corrupted.
        # TODO : Manage error when received message format is incorrect.
        self.role = role
        self._derived_password = derived_password
        self._password_salt = password_salt
        self._last_step = 0
        self._peer_public_key = None
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        self._symmetric_encryption_key = None
        self._authentication_information = authentication_information
        self._authentication_approved = False
        self._connection_status = HandShake.CONNECTION_STATUS_INCOMPLETE
        if allowed_protocol_versions is None:
            allowed_protocol_versions = HandShake.PROTOCOL_VERSIONS_AVAILABLE
        if not all(i in HandShake.PROTOCOL_VERSIONS_AVAILABLE for i in allowed_protocol_versions):
            raise ValueError("All allowed protocol versions must be present in HandShake.PROTOCOL_VERSIONS_AVAILABLE.")
        self._allowed_protocol_versions = [version for version in HandShake.PROTOCOL_VERSIONS_AVAILABLE if
                                           version in allowed_protocol_versions]
        self._client_protocol_versions = None
        self._time_creation = time.time()

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
        if self._connection_status == HandShake.CONNECTION_STATUS_FAILED:
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_FAILED_TOPIC)

        if self.role == HandShake.CLIENT:
            if self._last_step == HandShake.SERVER_KEY_SHARE_TOPIC:
                # TODO : Change this message into json.
                public_bytes = self._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                           format=serialization.PublicFormat.
                                                                           SubjectPublicKeyInfo)
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CLIENT_KEY_SHARE_TOPIC,
                                  payload=public_bytes)
            if self._last_step == HandShake.AUTHENTICATION_REQUIRED_TOPIC:
                # TODO : Add random bytes to add noise.
                # TODO : Send authentication information as a dict.
                # TODO : Send which authentication method the client will use.
                # TODO : Send connection failed when the client cannot provide authentication information.
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.AUTHENTICATION_TOPIC,
                                  payload=self._encrypt(self._authentication_information))
            payload = str.encode(
                json.dumps({HandShake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME: self._allowed_protocol_versions}),
                "utf8")
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_REQUEST_TOPIC, payload=payload)

        if self.role == HandShake.SERVER:
            if self._last_step == HandShake.CONNECTION_REQUEST_TOPIC:
                public_bytes = bytes.decode(
                    self._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.
                                                                SubjectPublicKeyInfo), "ascii")
                protocol_version = ""
                for version in self._client_protocol_versions:
                    if version in self._allowed_protocol_versions:
                        protocol_version = version
                if protocol_version == "":
                    self._connection_status = HandShake.CONNECTION_STATUS_FAILED
                    return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_FAILED_TOPIC)
                payload = str.encode(
                    json.dumps({HandShake.SELECTED_PROTOCOL_VERSION_KEY_NAME: protocol_version,
                                HandShake.SERVER_PUBLIC_KEY_KEY_NAME: public_bytes}),
                    "utf8")
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.SERVER_KEY_SHARE_TOPIC, payload=payload)
            if self._last_step == HandShake.CLIENT_KEY_SHARE_TOPIC and self._derived_password is None:
                self._connection_status = HandShake.CONNECTION_STATUS_APPROVED
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_APPROVED_TOPIC)
            # If authentication is required
            if self._last_step == HandShake.CLIENT_KEY_SHARE_TOPIC and self._derived_password is not None:
                payload = str.encode(json.dumps(
                    {HandShake.AUTHENTICATION_METHODS_AVAILABLE_KEY_NAME: HandShake.AUTHENTICATION_METHODS_AVAILABLE}),
                    "utf8")
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.AUTHENTICATION_REQUIRED_TOPIC,
                                  payload=payload)
            if self._last_step == HandShake.AUTHENTICATION_TOPIC and self._derived_password is not None:
                if self._authentication_approved:
                    self._connection_status = HandShake.CONNECTION_STATUS_APPROVED
                    return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_APPROVED_TOPIC)
                self._connection_status = HandShake.CONNECTION_STATUS_FAILED
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_FAILED_TOPIC)
            return None

    def add_message(self, msg: UDPMessage) -> NoReturn:
        """Handle given message and change HandShake state if needed.

        :param msg: The UDPMessage to read.
        """
        msg_id = int.from_bytes(msg.msg_id, 'little')
        msg_topic = int.from_bytes(msg.topic, 'little')
        if msg_id != codes.HANDSHAKE:
            return
        if msg_topic == HandShake.CONNECTION_FAILED_TOPIC:
            self._connection_status = HandShake.CONNECTION_STATUS_FAILED
        if msg_topic == HandShake.CONNECTION_REQUEST_TOPIC:
            payload = json.loads(bytes.decode(msg.payload, "utf8"))
            self._client_protocol_versions = payload[HandShake.PROTOCOL_VERSIONS_AVAILABLE_KEY_NAME]
            self._last_step = msg_topic
        if msg_topic == HandShake.SERVER_KEY_SHARE_TOPIC:
            self._last_step = msg_topic
            payload = json.loads(bytes.decode(msg.payload, "utf8"))
            self._peer_public_key = serialization.load_pem_public_key(
                str.encode(payload[HandShake.SERVER_PUBLIC_KEY_KEY_NAME], 'ascii'))
            self._symmetric_encryption_key = derive_key_hkdf(key=self.get_shared_key(), length=32)
        if msg_topic == HandShake.CLIENT_KEY_SHARE_TOPIC:
            self._last_step = msg_topic
            self._peer_public_key = serialization.load_pem_public_key(msg.payload, )
            self._symmetric_encryption_key = derive_key_hkdf(key=self.get_shared_key(), length=32)
        if msg_topic == HandShake.AUTHENTICATION_REQUIRED_TOPIC:
            self._last_step = msg_topic
        if msg_topic == HandShake.AUTHENTICATION_TOPIC:
            self._last_step = msg_topic
            self._authentication_approved = self._verify_password(self._decrypt(msg.payload))
        if msg_topic == HandShake.CONNECTION_APPROVED_TOPIC:
            self._connection_status = HandShake.CONNECTION_STATUS_APPROVED

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
        nonce = os.urandom(HandShake.NONCE_LENGTH)
        return nonce + chacha.encrypt(nonce, data, b"")

    def _decrypt(self, encrypted_message: bytes) -> bytes:
        """Decrypt data encrypted with _encrypt.

        :param encrypted_message: The data encrypted with _encrypt that need to be decrypted.

        :return: The decrypted data as bytes.
        """
        chacha = ChaCha20Poly1305(self._symmetric_encryption_key)
        return chacha.decrypt(encrypted_message[:HandShake.NONCE_LENGTH], encrypted_message[HandShake.NONCE_LENGTH:],
                              b"")

    def get_status(self) -> str:
        """Return the current status of the HandShake.

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
        self._connection_status = HandShake.CONNECTION_STATUS_FAILED

    def time_creation(self) -> float:
        """Return the time of creation of the instance.

        :return: The time of creation of the instance.
        """
        return self._time_creation
