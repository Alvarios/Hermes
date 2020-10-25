# -*- coding: utf-8 -*-
"""Implementation of a connection manager for secure encryption key exchanges.

This module provides a connection manager for secure encryption key exchanges.
"""

from typing import Optional, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import cryptography
from hermes.messages.UDPMessage import UDPMessage
from cryptography.hazmat.primitives import hashes, serialization
import numpy as np


class ConnectionManager:
    """A class that manage secure connection messages exchange between a server and a client.

        Constants :
            SERVER : Value that tell the ConnectionManager role is server.
            CLIENT : Value that tell the ConnectionManager role is client.
            GET_PUBLIC_KEY_ID : The message id corresponding to get public key request.
            PUT_PUBLIC_KEY_ID : The message id corresponding to put public key message.
            PUT_PASSWORD_MESSAGE_ID : The message id corresponding to put password.
            END_CONNECTION_ID : The message id corresponding to the end of the connection creation.
            RANDOM_NUMBER_LEN : The number of random bytes used for encrypted messages.
            RSA_PADDING : The padding used for encryption with rsa keys.

        Attributes :
            role : The role of the current ConnectionManager (client or server).
            hash_pass : The password as bytes needed for encryption key request.
            encryption_key : A key used for encryption. It will be given to the client if it send the correct pass.
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
    END_CONNECTION_ID = 30
    RANDOM_NUMBER_LEN = 8
    RSA_PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def __init__(self, role: Optional[str] = SERVER, hash_pass: Optional[Union[None, bytes]] = None,
                 encryption_key: Optional[Union[None, bytes]] = None):
        self.role: str = role
        self.hash_pass: Union[None, bytes] = hash_pass
        self.encryption_key: Union[None, bytes] = encryption_key
        self._rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._send_public_key: bool = False
        self._remote_host_key: Union[None, bytes] = None
        self._password_correct: Union[None, bool] = None

    def add_message(self, msg: UDPMessage):
        if int.from_bytes(msg.msg_id, 'little') == ConnectionManager.GET_PUBLIC_KEY_ID:
            self._send_public_key = True
        if int.from_bytes(msg.msg_id, 'little') == ConnectionManager.PUT_PUBLIC_KEY_ID:
            self._remote_host_key = serialization.load_pem_public_key(msg.payload)
        if int.from_bytes(msg.msg_id, 'little') == ConnectionManager.PUT_PASSWORD_MESSAGE_ID:
            self._password_correct = msg.payload[ConnectionManager.RANDOM_NUMBER_LEN:] == self.hash_pass

    def next_message(self) -> UDPMessage:
        if self._send_public_key:
            self._send_public_key = False
            return UDPMessage(msg_id=ConnectionManager.PUT_PUBLIC_KEY_ID,
                              payload=self._rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                              format=serialization.PublicFormat.
                                                                              SubjectPublicKeyInfo))
        if self._remote_host_key is not None and self.role == ConnectionManager.CLIENT:
            encoder = serialization.load_pem_public_key(self._remote_host_key)
            return encoder.encrypt(self.get_password_message().to_bytes(), ConnectionManager.RSA_PADDING)
        if self._password_correct is False:
            return UDPMessage(msg_id=ConnectionManager.END_CONNECTION_ID)
        if self.role == ConnectionManager.CLIENT or self._password_correct:
            return UDPMessage(msg_id=ConnectionManager.GET_PUBLIC_KEY_ID)

    def get_password_message(self):
        return UDPMessage(msg_id=ConnectionManager.PUT_PASSWORD_MESSAGE_ID,
                          payload=ConnectionManager.get_random_bytes(
                              ConnectionManager.RANDOM_NUMBER_LEN) + self.hash_pass)

    @staticmethod
    def get_random_bytes(n_bytes: int):
        return np.random.randint(0, 255, dtype=np.uint8, size=n_bytes).tobytes()


if __name__ == "__main__":
    pass
