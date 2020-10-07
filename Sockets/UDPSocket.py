# -*- coding: utf-8 -*-
"""Implementation of a socket for UDP communication.

This module provides a socket for UDP communication.
"""
from typing import NoReturn, Optional, List, Tuple, Any, Union
from Messages.UDPMessage import UDPMessage
import socket
from threading import Thread
from cryptography.fernet import Fernet


class UDPSocket(Thread):
    """A socket for UDP communication.


        Attributes :
            encryption_in_transit : Define if the connection must be secure.
            max_queue_size : The max size of message queue.

    """

    def __init__(self, socket_ip: Optional[str] = "127.0.0.1", socket_port: Optional[int] = 50000,
                 encryption_in_transit: Optional[bool] = False, max_queue_size: Optional[int] = 100,
                 buffer_size: Optional[int] = 65543, key: Optional[Union[None, bytes]] = None) -> None:
        Thread.__init__(self)
        self.socket_ip = socket_ip
        self.socket_port = socket_port
        self.encryption_in_transit: bool = encryption_in_transit
        self.max_queue_size: int = max_queue_size
        self.buffer_size: int = buffer_size
        self.queue: List[Tuple[bytes, Any]] = []
        self.socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.is_running: bool = False
        self.key: bytes = key if key is not None else Fernet.generate_key()
        self.fernet_encoder = Fernet(self.key)

    def start_socket(self) -> NoReturn:
        self.is_running = True
        self.socket.bind((self.socket_ip, self.socket_port))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.start()

    def run(self) -> NoReturn:
        while self.is_running:
            self.listen()

    def stop_socket(self) -> NoReturn:
        self.is_running = False
        self.socket.shutdown(socket.SHUT_RD)
        self.socket.close()
        self.join()

    def listen(self) -> NoReturn:
        try:
            rcv_msg = self.socket.recvfrom(self.buffer_size)
            if rcv_msg == bytes():
                return
            if len(self.queue) >= self.max_queue_size:
                raise BufferError
            if self.encryption_in_transit:
                rcv_msg = (self.fernet_encoder.decrypt(rcv_msg[0]), rcv_msg[1])
            self.queue.append(rcv_msg)
        except OSError:
            pass

    def sendto(self, msg: Optional[bytes] = bytes,
               address_port: Optional[Union[Tuple[str, int], None]] = None) -> NoReturn:
        if self.encryption_in_transit:
            msg = self.fernet_encoder.encrypt(msg)
        try:
            self.socket.sendto(msg, address_port)
        except OSError:
            pass

    def pull(self):
        return self.queue.pop(0)

    def change_key(self, new_key: bytes):
        self.key = new_key
        self.fernet_encoder = Fernet(self.key)


if __name__ == "__main__":
    tst_1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    tst_2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    tst_1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tst = [1, 2]
    tst.append(3)
    print(tst.pop(0))
    print(tst)
