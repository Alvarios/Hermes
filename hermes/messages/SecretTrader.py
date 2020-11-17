# -*- coding: utf-8 -*-
"""Implementation of a secret trader for secure secret exchanges.

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


class SecretTrader:
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
            SERVER : Value that tell the SecretTrader role is server.
            CLIENT : Value that tell the SecretTrader role is client.
            GET_PUBLIC_KEY_ID : The message id corresponding to get public key request.
            PUT_PUBLIC_KEY_ID : The message id corresponding to put public key message.
            PUT_PASSWORD_MESSAGE_ID : The message id corresponding to put password.
            PUT_SECRET_MESSAGE_ID : The message id to put secret.
            END_CONNECTION_ID : The message id corresponding to the end of the connection creation.
            RANDOM_NUMBER_LEN : The number of random bytes used for encrypted messages.
            RSA_PADDING : The padding used for encryption with rsa keys.

        Attributes :
            role : The role of the current SecretTrader (client or server).
            _hash_pass : The password as bytes needed for encryption key request.
            _secret : A key used for encryption. It will be given to the client if it send the correct pass.
            _rsa_key : The rsa key used for this connection.
            _send_public_key : A flag used to know if a get public key request have been received.
            _remote_host_key : The remote host public key (None if it is currently unknown).
            _password_correct : A flag that tell if the given password is correct.
    """

    SERVER = "server"
    CLIENT = "client"
    GET_PUBLIC_KEY_ID = 10
    PUT_PUBLIC_KEY_ID = 20
    PUT_PASSWORD_MESSAGE_ID = 21
    PUT_SECRET_MESSAGE_ID = 22
    END_CONNECTION_ID = 30
    RANDOM_NUMBER_LEN = 8
    RSA_PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def __init__(self, role: Optional[str] = SERVER, hash_pass: Optional[Union[None, bytes]] = None,
                 secret: Optional[Union[None, bytes]] = None) -> None:
        """Create a new SecretTrader object with given parameter.

        :param role: The role of the current SecretTrader (client or server).
        :param hash_pass: The password as bytes needed for encryption key request.
        :param secret : A key used for encryption. Required if role is server.
        """
        self.role: str = role
        self._hash_pass: Union[None, bytes] = hash_pass
        if role == SecretTrader.SERVER and secret is None:
            raise ValueError
        self._secret: Union[None, bytes] = secret
        self._rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._send_public_key: bool = False
        self._remote_host_key = None
        self._password_correct: Union[None, bool] = None

    def add_message(self, msg: UDPMessage) -> NoReturn:
        """Handle given message and change instance state if needed.

        :param msg: The UDPMessage to read.
        """
        if int.from_bytes(msg.msg_id, 'little') == SecretTrader.GET_PUBLIC_KEY_ID:
            self._send_public_key = True
        if int.from_bytes(msg.msg_id, 'little') == SecretTrader.PUT_PUBLIC_KEY_ID:
            self._remote_host_key = serialization.load_pem_public_key(msg.payload)
        if int.from_bytes(msg.msg_id, 'little') == SecretTrader.PUT_PASSWORD_MESSAGE_ID:
            payload = self._rsa_key.decrypt(msg.payload, SecretTrader.RSA_PADDING)
            self._password_correct = payload[SecretTrader.RANDOM_NUMBER_LEN:] == self._hash_pass
        if int.from_bytes(msg.msg_id, 'little') == SecretTrader.PUT_SECRET_MESSAGE_ID:
            payload = self._rsa_key.decrypt(msg.payload, SecretTrader.RSA_PADDING)
            self._secret = payload[SecretTrader.RANDOM_NUMBER_LEN:]

    def next_message(self) -> UDPMessage:
        """Return the next message to send to remote host based on current instance state.

        :return next_message: A UDPMessage to send to remote host to continue key exchange process.
        """
        if self._send_public_key:
            self._send_public_key = False
            return UDPMessage(msg_id=SecretTrader.PUT_PUBLIC_KEY_ID,
                              payload=self._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                              format=serialization.PublicFormat.
                                                                              SubjectPublicKeyInfo))
        if self._remote_host_key is not None and self.role == SecretTrader.CLIENT:
            return self._get_password_message()
        if self._password_correct is False:
            return UDPMessage(msg_id=SecretTrader.END_CONNECTION_ID)
        if self._password_correct and self._remote_host_key is not None:
            return self._get_secret_message()
        if self.role == SecretTrader.CLIENT or self._password_correct:
            return UDPMessage(msg_id=SecretTrader.GET_PUBLIC_KEY_ID)

    def _get_password_message(self) -> UDPMessage:
        """Return a UDPMessage that contain the hashed password encrypted with remote host public key.

        :return password_message: The message that contain the hashed password.
        """
        if self._remote_host_key is not None:
            return UDPMessage(msg_id=SecretTrader.PUT_PASSWORD_MESSAGE_ID,
                              payload=self._remote_host_key.encrypt(SecretTrader._get_random_bytes(
                                  SecretTrader.RANDOM_NUMBER_LEN) + self._hash_pass, SecretTrader.RSA_PADDING))

    def _get_secret_message(self) -> UDPMessage:
        """Return a UDPMessage that contain the encryption key encrypted with remote host public key.

        :return password_message: The message that contain the encryption key.
        """
        if self._remote_host_key is not None:
            return UDPMessage(msg_id=SecretTrader.PUT_SECRET_MESSAGE_ID,
                              payload=self._remote_host_key.encrypt(SecretTrader._get_random_bytes(
                                  SecretTrader.RANDOM_NUMBER_LEN) + self._secret,
                                                      SecretTrader.RSA_PADDING))

    @staticmethod
    def _get_random_bytes(n_bytes: int) -> bytes:
        """Return random bytes of length n_bytes

        :param n_bytes: The length of the bytes to return.

        :return random_bytes: The random bytes with given length.
        """
        return np.random.randint(0, 255, dtype=np.uint8, size=n_bytes).tobytes()

    @staticmethod
    def hash_password(password: Union[str, bytes], hash_alg=hashes.SHA256()) -> bytes:
        """Return a hash of given string or bytes.

        :param password: The str or bytes to hash.
        :param hash_alg: The algorithm used to hash the input password.

        :return hash_pass: The hash of the input password.
        """
        digest = hashes.Hash(hash_alg)
        digest.update(bytes(password))
        return digest.finalize()
