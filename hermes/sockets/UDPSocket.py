# -*- coding: utf-8 -*-
"""Implementation of a socket for UDP communication.

This module provides a socket for UDP communication.
"""
import time
from typing import NoReturn, Optional, List, Tuple, Any, Union
import socket
from threading import Thread
from cryptography.fernet import Fernet
import multiprocessing as mp


class UDPSocket:
    """A socket for UDP communication.


        Attributes :
            socket_ip: The ip used to bind the socket.
            socket_port: The port used to bind the socket.
            encryption_in_transit : Define if the messages must be encrypted.
            max_queue_size : The max size of message queue.
            buffer_size : The max size of the received message buffer.
            queue : The queue that stores received messages.
            socket : The socket object used for udp communication.
            is_running : A flag that specify if the socket is currently running.
            key : The encryption key used to encrypt message. If no value is provided it will generate a new one.
            fernet_encoder : The encoder used to encrypt and decrypt messages.
            enable_multicast : Specify if the socket can use multicast.
            multicast_ttl : The TTL used for multicast.
            must_listen : Define if the socket must listen for messages.
            setblocking : Define if the socket must block.
            run_new_process : Specify if the UDPSocket instance must be run in a new process.
            internal_pipe : Internal side of the pipe used for communication with the process.
            external_pipe : External side of the pipe used for communication with the process.

    """

    def __init__(self, socket_ip: Optional[str] = "127.0.0.1", socket_port: Optional[int] = 50000,
                 encryption_in_transit: Optional[bool] = False, max_queue_size: Optional[int] = 100,
                 buffer_size: Optional[int] = 65543, key: Optional[Union[None, bytes]] = None,
                 enable_multicast: Optional[bool] = False, multicast_ttl: Optional[int] = 2,
                 must_listen: Optional[bool] = True, setblocking: Optional[bool] = True,
                 run_new_process: Optional[bool] = False) -> None:
        """Create a new UDPSocket object with given parameters.

        :param socket_ip: The ip used to bind the socket.
        :param socket_port: The port used to bind the socket.
        :param encryption_in_transit: Define if the messages must be encrypted.
        :param max_queue_size: The max size of message queue.
        :param buffer_size: The max size of the received message buffer.
        :param key: The encryption key used to encrypt message. If no value is provided it will generate a new one.
        :param enable_multicast: Specify if the socket can use multicast.
        :param multicast_ttl: The TTL used for multicast.
        :param must_listen: Define if the socket must listen for messages.
        :param setblocking: Define if the socket must block.
        :param run_new_process: Specify if the UDPSocket instance must be run in a new process.
        """
        self.socket_ip = socket_ip
        self.socket_port = socket_port
        self.encryption_in_transit: bool = encryption_in_transit
        self.max_queue_size: int = max_queue_size
        self.buffer_size: int = buffer_size
        self.queue: List[Tuple[bytes, Any]] = []
        self.socket: Union[socket.socket, None] = None
        self.is_running: bool = False
        self.key: bytes = key if key is not None else Fernet.generate_key()
        self.fernet_encoder: Union[Fernet, None] = None
        self.enable_multicast: bool = enable_multicast
        self.multicast_ttl: int = multicast_ttl
        self.must_listen = must_listen
        self.setblocking = setblocking
        self.run_new_process = run_new_process
        self.internal_pipe, self.external_pipe = mp.Pipe()

    def start(self) -> NoReturn:
        """Start a new thread or a new process for asynchronous camera reading.

        :return eye: The current instance of the class.
        """
        if self.run_new_process is False:
            self._start()
        else:
            mp.Process(target=self._start).start()
        return self

    def _start(self) -> NoReturn:
        """Start the thread of the class."""
        self._work()

    def stop(self) -> NoReturn:
        """Call to _stop function."""
        if self.run_new_process is False:
            return self._stop()
        self.external_pipe.send((UDPSocket._stop, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _stop(self) -> NoReturn:
        """Stop the listening thread."""
        self.is_running = False
        try:
            self.socket.close()
        except:
            pass

    def _work(self):
        """Execute the setup and the main loop of the class."""
        self._setup()
        self._loop()

    def _setup(self):
        """Setup function of the class."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.fernet_encoder = Fernet(self.key)
        self.socket.setblocking(self.setblocking)
        self.socket.bind((self.socket_ip, self.socket_port))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.enable_multicast:
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.multicast_ttl)
        self.is_running = True
        if self.must_listen:
            Thread(target=self._listen, args=()).start()

    def _loop(self):
        """Main loop of the class"""
        if self.run_new_process is False:
            return
        while self.is_running:
            if self.run_new_process and self.internal_pipe.poll():
                command = self.internal_pipe.recv()
                if type(command) is tuple:
                    self.internal_pipe.send(command[0](self, **command[1]))

    def _listen(self) -> NoReturn:
        """Add incoming messages to the queue and decrypt it if needed."""
        while self.is_running:
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
        """Call to _sendto.

        :param msg: The data to send.
        :param address_port: A tuple of ip address and port of the target network endpoint.
        """
        if self.run_new_process is False:
            return self._sendto(msg=msg, address_port=address_port)
        self.external_pipe.send((UDPSocket._sendto, {"msg": msg, "address_port": address_port}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _sendto(self, msg: Optional[bytes] = bytes,
                address_port: Optional[Union[Tuple[str, int], None]] = None) -> NoReturn:
        """Send a message to given network endpoint.

        :param msg: The data to send.
        :param address_port: A tuple of ip address and port of the target network endpoint.
        """
        if self.encryption_in_transit:
            msg = self.fernet_encoder.encrypt(msg)
        try:
            self.socket.sendto(msg, address_port)
        except OSError:
            pass

    def in_waiting(self):
        if self.run_new_process is False:
            return self._in_waiting()
        self.external_pipe.send((UDPSocket._in_waiting, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _in_waiting(self):
        """Return True the queue is not empty

        :return in_waiting: A bool that tell if the queue is empty.
        """
        return len(self.queue) != 0

    def pull(self) -> Tuple[bytes, Any]:
        if self.run_new_process is False:
            return self._pull()
        self.external_pipe.send((UDPSocket._pull, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _pull(self) -> Tuple[bytes, Any]:
        """Return the first message of the queue and remove it.

        :return msg_address_port: The first message of the queue.
        """
        return self.queue.pop(0)

    def change_key(self, new_key: bytes) -> NoReturn:
        if self.run_new_process is False:
            return self._change_key(new_key)
        self.external_pipe.send((UDPSocket._change_key, {"new_key": new_key}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _change_key(self, new_key: bytes) -> NoReturn:
        """Change the encryption key of the socket and create a new fernet_encoder.

        :param new_key: The new key to use for encryption.
        """
        self.key = new_key
        self.fernet_encoder = Fernet(self.key)

