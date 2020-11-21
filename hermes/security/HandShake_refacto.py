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

from typing import Optional, Union, NoReturn
from hermes.messages.UDPMessage import UDPMessage
from cryptography.hazmat.primitives import serialization
import hermes.messages.codes as codes
from cryptography.hazmat.primitives.asymmetric import ec
from hermes.security.utils import verify_password_scrypt


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

            CONNECTION_FAILED_TOPIC : UDPMessage topic used to inform connection failed.
            CONNECTION_REQUEST_TOPIC : UDPMessage topic used to inform a client want to create a connection.
            SERVER_KEY_SHARE_TOPIC : UDPMessage topic used to inform the server has send its public key.
            CLIENT_KEY_SHARE_TOPIC : UDPMessage topic used to inform the client has send its public key.
            CONNECTION_APPROVED_TOPIC : UDPMessage topic used to inform the connection has been approved by the server.
            AUTHENTICATION_REQUIRED_TOPIC : UDPMessage topic used to inform the authentication is required to approve
                                            the connection.

        Attributes :
            role : The role of the current HandShake (client or server).
            _derived_password : Only required for role server. The derived password used for authentication (if set
                                to None no authentication is required)
            _password_salt : Only required for role server. The salt used for key derivation corresponding to
                            _derived_password as bytes.
            _last_step : Stores the last validated step of the handshake.
            _peer_public_key : Stores the peer public key when it has been received.
            _private_key : Stores the ephemeral private key used for handshake.
    """

    SERVER = "server"
    CLIENT = "client"

    CONNECTION_FAILED_TOPIC = 0
    CONNECTION_REQUEST_TOPIC = 1
    SERVER_KEY_SHARE_TOPIC = 2
    CLIENT_KEY_SHARE_TOPIC = 3
    CONNECTION_APPROVED_TOPIC = 4
    AUTHENTICATION_REQUIRED_TOPIC = 5

    def __init__(self, role: Optional[str] = SERVER, derived_password: Optional[Union[None, bytes]] = None,
                 password_salt: Optional[Union[None, bytes]] = None) -> None:
        """Create a new HandShake object with given parameter.

        :param role: The role of the current HandShake (client or server).
        :param derived_password: The derived password to use for password verification as bytes. If None no
        authentication will be required during the handshake.
        :param password_salt : The salt used for key derivation corresponding to _derived_password as bytes.
        """
        self.role = role
        self._derived_password = derived_password
        self._password_salt = password_salt
        self._last_step = 0
        self._peer_public_key = None
        self._private_key = ec.generate_private_key(ec.SECP384R1())

    def verify_password(self, password_to_verify: bytes) -> bool:
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
        if self.role == HandShake.CLIENT:
            # TODO: Add all protocol version available in payload when connection request.
            if self._last_step == HandShake.SERVER_KEY_SHARE_TOPIC:
                public_bytes = self._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                           format=serialization.PublicFormat.
                                                                           SubjectPublicKeyInfo)
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CLIENT_KEY_SHARE_TOPIC,
                                  payload=public_bytes)
            return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_REQUEST_TOPIC)

        if self.role == HandShake.SERVER:
            if self._last_step == HandShake.CONNECTION_REQUEST_TOPIC:
                public_bytes = self._private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                           format=serialization.PublicFormat.
                                                                           SubjectPublicKeyInfo)
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.SERVER_KEY_SHARE_TOPIC,
                                  payload=public_bytes)
            if self._last_step == HandShake.CLIENT_KEY_SHARE_TOPIC and self._derived_password is None:
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_APPROVED_TOPIC)
            if self._last_step == HandShake.CLIENT_KEY_SHARE_TOPIC and self._derived_password is not None:
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.AUTHENTICATION_REQUIRED_TOPIC)
            return None

    def add_message(self, msg: UDPMessage) -> NoReturn:
        """Handle given message and change HandShake state if needed.

        :param msg: The UDPMessage to read.
        """
        msg_id = int.from_bytes(msg.msg_id, 'little')
        msg_topic = int.from_bytes(msg.topic, 'little')
        if msg_id != codes.HANDSHAKE:
            return
        if msg_topic == HandShake.CONNECTION_REQUEST_TOPIC:
            self._last_step = msg_topic
        if msg_topic == HandShake.SERVER_KEY_SHARE_TOPIC:
            self._last_step = msg_topic
            self._peer_public_key = serialization.load_pem_public_key(msg.payload, )
        if msg_topic == HandShake.CLIENT_KEY_SHARE_TOPIC:
            self._last_step = msg_topic
            self._peer_public_key = serialization.load_pem_public_key(msg.payload, )

    def get_shared_key(self) -> bytes:
        """Return the resulting key after Diffie-Hellman key exchange.

        :return: The shared key generated using ECDH as bytes.
        """
        return self._private_key.exchange(ec.ECDH(), self._peer_public_key)
