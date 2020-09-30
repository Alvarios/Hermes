# -*- coding: utf-8 -*-
"""Implementation of a socket for UDP communication.

This module provides a socket for UDP communication.
"""
from typing import NoReturn, Optional, List, Tuple, Any, Union
from Messages.UDPMessage import UDPMessage
import socket
from threading import Thread


class UDPSocket(Thread):
    """A socket for UDP communication.


        Attributes :
            secure_connection : Define if the connection must be secure.
            max_queue_size : The max size of message queue.

    """

    def __init__(self, socket_ip: Optional[str] = "127.0.0.1", socket_port: Optional[int] = 50000,
                 secure_connection: Optional[bool] = False, max_queue_size: Optional[int] = 100,
                 buffer_size: Optional[int] = 65543) -> None:
        Thread.__init__(self)
        self.socket_ip = socket_ip
        self.socket_port = socket_port
        self.secure_connection: bool = secure_connection
        self.max_queue_size: int = max_queue_size
        self.buffer_size: int = buffer_size
        self.queue: List[Tuple[bytes, Any]] = []
        self.socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.is_running: bool = False

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
            if len(self.queue) >= self.max_queue_size:
                raise BufferError
            self.queue.append(self.socket.recvfrom(self.buffer_size))
        except OSError:
            pass

    def sendto(self, msg: Optional[bytes] = bytes,
               address_port: Optional[Union[Tuple[str, int], None]] = None) -> NoReturn:
        try:
            self.socket.sendto(msg, address_port)
        except OSError:
            pass


if __name__ == "__main__":
    tst_1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    tst_2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    tst_1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
