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
            RANDOM_NUMBER_TYPE : The numpy type used for random number generation.

        Attributes :



    """
    SERVER = "server"
    CLIENT = "client"
    GET_PUBLIC_KEY_ID = 10
    PUT_PUBLIC_KEY_ID = 20
    PUT_PASSWORD_MESSAGE_ID = 21
    RANDOM_NUMBER_TYPE = np.uint64

    def __init__(self, role: Optional[str] = SERVER, hash_pass: Optional[Union[None, bytes]] = None,
                 encryption_key: Optional[Union[None, bytes]] = None):
        self.role: str = role
        self.hash_pass: Union[None, bytes] = hash_pass
        self.encryption_key: Union[None, bytes] = encryption_key
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._send_public_key: bool = False
        self._remote_host_key = None

    def add_message(self, msg: UDPMessage):
        if int.from_bytes(msg.msg_id, 'little') == ConnectionManager.GET_PUBLIC_KEY_ID:
            self._send_public_key = True
        if int.from_bytes(msg.msg_id, 'little') == ConnectionManager.PUT_PUBLIC_KEY_ID:
            self._remote_host_key = serialization.load_pem_public_key(msg.payload)

    def next_message(self) -> UDPMessage:
        if self._send_public_key:
            self._send_public_key = False
            return UDPMessage(msg_id=ConnectionManager.PUT_PUBLIC_KEY_ID,
                              payload=self.rsa_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                             format=serialization.PublicFormat.
                                                                             SubjectPublicKeyInfo))
        if self.role == ConnectionManager.CLIENT:
            return UDPMessage(msg_id=ConnectionManager.GET_PUBLIC_KEY_ID)

    # TODO : test this
    # def get_password_message(self):
    #     return UDPMessage(msg_id=ConnectionManager.PUT_PASSWORD_MESSAGE_ID,
    #                       payload=ConnectionManager.get_random_number().tobytes() + self.hash_pass)

    @staticmethod
    def get_random_number():
        return np.random.randint(0, np.iinfo(ConnectionManager.RANDOM_NUMBER_TYPE).max,
                                 dtype=ConnectionManager.RANDOM_NUMBER_TYPE)
