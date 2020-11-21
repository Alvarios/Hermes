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
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from hermes.messages.UDPMessage import UDPMessage
from cryptography.hazmat.primitives import hashes, serialization
import numpy as np
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey, AlreadyFinalized
import hermes.messages.codes as codes
from cryptography.hazmat.primitives.asymmetric import ec


class HandShake:
    """A class can manage secret exchange between two instances of this class, one with a role of server
    the other one with the role of client. It is designed to exchange symmetric encryption key but can be
    used to exchange any secret.

        The communication between client and server work as following :

            Step 1 : Client ask server's public key
            Step 2 : Server send its public key to server.
            Step 3 Client send hashed password encrypted with server public key to server
            Step 4 (if password incorrect) : Server send end connection message to client.
            Step 4 (if password correct) : Server ask client's public key.
            Step 5 : Client send its public key to server.
            Step 7 : Server send its secret encrypted with client's public key to client.

        Constants :


        Attributes :

    """

    SERVER = "server"
    CLIENT = "client"

    CONNECTION_FAILED_TOPIC = 0
    CONNECTION_REQUEST_TOPIC = 1
    SERVER_KEY_SHARE_TOPIC = 2
    CLIENT_KEY_SHARE_TOPIC = 3
    CONNECTION_APPROVED_TOPIC = 4

    def __init__(self, role: Optional[str] = SERVER, derived_password: Optional[Union[None, bytes]] = None,
                 password_salt: Optional[Union[None, bytes]] = None) -> None:
        self.role = role
        self.derived_password = derived_password
        self.password_salt = password_salt
        self._last_step = 0
        self._peer_public_key = None
        self._private_key = ec.generate_private_key(
            ec.SECP384R1()
        )

    def verify_password(self, password_to_verify):
        if self.derived_password is None:
            return True
        password_correct = False
        kdf = Scrypt(
            salt=self.password_salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        try:
            kdf.verify(password_to_verify, self.derived_password)
            password_correct = True
        except InvalidKey:
            pass
        except AlreadyFinalized:
            pass
        return password_correct

    def next_message(self) -> Union[None, UDPMessage]:
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
            if self._last_step == HandShake.CLIENT_KEY_SHARE_TOPIC:
                return UDPMessage(msg_id=codes.HANDSHAKE, topic=HandShake.CONNECTION_APPROVED_TOPIC)
            return None

    def add_message(self, msg: UDPMessage):
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

    def get_shared_key(self):
        return self._private_key.exchange(ec.ECDH(), self._peer_public_key)
