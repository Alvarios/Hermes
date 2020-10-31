# -*- coding: utf-8 -*-
"""Implementation of a secret trader for secure key exchanges.

This module provides a secret trader for secure key exchanges.
"""

from typing import Optional, Union, NoReturn
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from hermes.messages.UDPMessage import UDPMessage
from cryptography.hazmat.primitives import hashes, serialization
import numpy as np


class SecretTrader:
    """A class that manage secure key exchanges between a server and a client.

        Constants :
            SERVER : Value that tell the SecretTrader role is server.
            CLIENT : Value that tell the SecretTrader role is client.
            GET_PUBLIC_KEY_ID : The message id corresponding to get public key request.
            PUT_PUBLIC_KEY_ID : The message id corresponding to put public key message.
            PUT_PASSWORD_MESSAGE_ID : The message id corresponding to put password.
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
    PUT_ENCRYPTION_KEY_MESSAGE_ID = 22
    END_CONNECTION_ID = 30
    RANDOM_NUMBER_LEN = 8
    RSA_PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def __init__(self, role: Optional[str] = SERVER, hash_pass: Optional[Union[None, bytes]] = None,
                 secret: Optional[Union[None, bytes]] = None) -> None:
        """Create a new SecretTrader object with given parameter.

        This class can manage _secret exchange between two instances of this class, one with a role of server
        the other one with the role of client.

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
        self._remote_host_key: Union[None, bytes] = None
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
            return self._get_key_message()
        if self.role == SecretTrader.CLIENT or self._password_correct:
            return UDPMessage(msg_id=SecretTrader.GET_PUBLIC_KEY_ID)

    def _get_password_message(self) -> UDPMessage:
        """Return a UDPMessage that contain the hashed password encrypted with remote host public key.

        :return password_message: The message that contain the hashed password.
        """
        if self._remote_host_key is not None:
            encoder = serialization.load_pem_public_key(self._remote_host_key)
            return UDPMessage(msg_id=SecretTrader.PUT_PASSWORD_MESSAGE_ID,
                              payload=encoder.encrypt(SecretTrader._get_random_bytes(
                                  SecretTrader.RANDOM_NUMBER_LEN) + self._hash_pass, SecretTrader.RSA_PADDING))

    def _get_key_message(self) -> UDPMessage:
        """Return a UDPMessage that contain the encryption key encrypted with remote host public key.

        :return password_message: The message that contain the encryption key.
        """
        if self._remote_host_key is not None:
            encoder = serialization.load_pem_public_key(self._remote_host_key)
            return UDPMessage(msg_id=SecretTrader.PUT_ENCRYPTION_KEY_MESSAGE_ID,
                              payload=encoder.encrypt(SecretTrader._get_random_bytes(
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
