# -*- coding: utf-8 -*-
"""Implementation of a socket for UDP communication.


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
from __future__ import annotations
# TODO: Remove future import in the future (python version > 3.10?)
from typing import NoReturn, Optional, List, Tuple, Any, Union
import socket
from threading import Thread
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import multiprocessing as mp

from hermes.domain.AsynchronousIPChannel import AsynchronousIPChannel
from hermes.security.utils import generate_key_32


class AsyncUDPChannel(AsynchronousIPChannel):
    """A socket for UDP communication.

        Constants :
            NONCE_LENGTH : The length of nonce used for encryption (in bytes).

        Attributes :
            socket_ip: The ip used to bind the socket.
            socket_port: The port used to bind the socket.
            encryption_in_transit : Define if the messages must be encrypted.
            max_queue_size : The max size of message queue.
            buffer_size : The max size of the received message buffer.
            queue : The queue that stores received messages.
            socket : The socket object used for udp communication.
            _is_running : A flag that specify if the socket is currently
            running.
            _key : The encryption _key used to encrypt message. If no value is
            provided it will generate a new one.
            encoder : The encoder used to encrypt and decrypt messages.
            enable_multicast : Specify if the socket can use multicast.
            multicast_ttl : The TTL used for multicast.
            must_listen : Define if the socket must listen for messages.
            setblocking : Define if the socket must block.
            _run_new_process : Specify if the UDPSocket instance must be run
            in a new process.
            _internal_pipe : Internal side of the pipe used for communication
            with the process.
            _external_pipe : External side of the pipe used for communication
            with the process.
    """
    NONCE_LENGTH = 12

    def __init__(self, socket_ip: Optional[str] = "127.0.0.1",
                 socket_port: Optional[int] = 50000,
                 encryption_in_transit: Optional[bool] = False,
                 max_queue_size: Optional[int] = 100,
                 buffer_size: Optional[int] = 65543,
                 key: Optional[Union[None, bytes]] = None,
                 enable_multicast: Optional[bool] = False,
                 multicast_ttl: Optional[int] = 2,
                 must_listen: Optional[bool] = True,
                 setblocking: Optional[bool] = True,
                 run_new_process: Optional[bool] = False) -> None:
        """Create a new UDPSocket object with given parameters.

        :param socket_ip: The ip used to bind the socket.
        :param socket_port: The port used to bind the socket.
        :param encryption_in_transit: Define if the messages must be encrypted.
        :param max_queue_size: The max size of message queue.
        :param buffer_size: The max size of the received message buffer.
        :param key: The encryption _key used to encrypt message. If no value
        is provided it will generate a new one.
        :param enable_multicast: Specify if the socket can use multicast.
        :param multicast_ttl: The TTL used for multicast.
        :param must_listen: Define if the socket must listen for messages.
        :param setblocking: Define if the socket must block.
        :param run_new_process: Specify if the UDPSocket instance must be run
         in a new process.
        """
        self.socket_ip = socket_ip
        self.socket_port = socket_port
        self.encryption_in_transit: bool = encryption_in_transit
        self.max_queue_size: int = max_queue_size
        self.buffer_size: int = buffer_size
        self.queue: List[Tuple[bytes, Any]] = []
        self.socket: Union[socket.socket, None] = None
        self.is_running: bool = False
        self._key: bytes = key if key is not None else generate_key_32()
        self.encoder: Union[ChaCha20Poly1305, None] = None
        self.enable_multicast: bool = enable_multicast
        self.multicast_ttl: int = multicast_ttl
        self.must_listen = must_listen
        self.setblocking = setblocking
        self.run_new_process = run_new_process
        self.internal_pipe, self.external_pipe = mp.Pipe()

    def start(self) -> AsyncUDPChannel:
        """Start a new thread or a new process for asynchronous camera reading.

        :return eye: The current instance of the class.
        """
        if self.run_new_process is False:
            self._start()
        else:
            mp.Process(target=self._start).start()
        return self

    def _start(self) -> None:
        """Start the thread of the class."""
        self._work()

    def stop(self) -> None:
        """Call to _stop function."""
        if self.run_new_process is False:
            return self._stop()
        self.external_pipe.send((AsyncUDPChannel._stop, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _stop(self) -> None:
        """Stop the listening thread."""
        self.is_running = False
        try:
            self.socket.close()
        except:
            pass

    def _work(self) -> NoReturn:
        """Execute the setup and the main loop of the class."""
        self._setup()
        self._loop()

    def _setup(self) -> None:
        """Setup function of the class."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                    socket.IPPROTO_UDP)
        self.encoder = ChaCha20Poly1305(self._key)
        self.socket.setblocking(self.setblocking)
        self.socket.bind((self.socket_ip, self.socket_port))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.enable_multicast:
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                                   self.multicast_ttl)
        self.is_running = True
        if self.must_listen:
            Thread(target=self._listen, args=()).start()

    def _loop(self) -> NoReturn:
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
                    rcv_msg = (self._decrypt(rcv_msg[0]), rcv_msg[1])
                self.queue.append(rcv_msg)
            except OSError:
                pass

    def sendto(self, msg: Optional[bytes] = bytes(),
               address_port: Optional[Union[Tuple[str, int], None]] = None,
               skip_encryption: Optional[bool] = False) -> None:
        """Call to _sendto.

        :param msg: The data to send.
        :param address_port: A tuple of ip address and port of the target
        network endpoint.
        :param skip_encryption: If encryption_in_transit is set,
        skip_encryption will disable the encryption for this message.
        """
        if self.run_new_process is False:
            return self._sendto(msg=msg, address_port=address_port,
                                skip_encryption=skip_encryption)
        self.external_pipe.send(
            (AsyncUDPChannel._sendto,
             {"msg": msg, "address_port": address_port,
              "skip_encryption": skip_encryption}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _sendto(self, msg: Optional[bytes] = bytes(),
                address_port: Optional[Union[Tuple[str, int], None]] = None,
                skip_encryption: Optional[bool] = False) -> None:
        """Send a message to given network endpoint.

        :param msg: The data to send.
        :param address_port: A tuple of ip address and port of the target
        network endpoint.
        :param skip_encryption: If encryption_in_transit is set,
        skip_encryption will disable the encryption for this message.
        """
        if self.encryption_in_transit and not skip_encryption:
            msg = self._encrypt(msg)
        try:
            self.socket.sendto(msg, address_port)
        except OSError:
            pass

    def message_available(self) -> bool:
        """Return True if messages are available in the queue.

        :return: A bool that tell if the queue is empty.
        """
        if self.run_new_process is False:
            return self._message_available()
        self.external_pipe.send((AsyncUDPChannel._message_available, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _message_available(self) -> bool:
        """Return True the queue is not empty.

        :return: A bool that tell if the queue is empty.
        """
        return len(self.queue) != 0

    def pull(self) -> Tuple[bytes, Any]:
        """Return the first message of the queue and remove it.

        :return: The first message of the queue.
        """
        if self.run_new_process is False:
            return self._pull()
        self.external_pipe.send((AsyncUDPChannel._pull, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _pull(self) -> Tuple[bytes, Any]:
        """Return the first message of the queue and remove it.

        :return: The first message of the queue.
        """
        return self.queue.pop(0)

    def change_key(self, new_key: bytes) -> None:
        """Change the encryption _key of the socket and create a new encoder.

        :param new_key: The new _key to use for encryption.
        """
        if self.run_new_process is False:
            return self._change_key(new_key)
        self.external_pipe.send(
            (AsyncUDPChannel._change_key, {"new_key": new_key}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _change_key(self, new_key: bytes) -> None:
        """Change the encryption _key of the socket and create a new encoder.

        :param new_key: The new _key to use for encryption.
        """
        self._key = new_key
        self.encoder = ChaCha20Poly1305(self._key)

    def _encrypt(self, msg: bytes) -> bytes:
        """Internal function used to encrypt data when encryption in transit
        is enabled.

        :param msg: The message to encrypt.

        :return: The message encrypted.
        """
        nonce = os.urandom(AsyncUDPChannel.NONCE_LENGTH)
        return nonce + self.encoder.encrypt(nonce, msg, b"")

    def _decrypt(self, encrypted_message: bytes) -> bytes:
        """Internal function used to decrypt data when encryption in transit
        is enabled.

        :param encrypted_message: The message to decrypt.

        :return: The message decrypted if it is possible else the input
         message.
        """
        try:
            return self.encoder.decrypt(
                encrypted_message[:AsyncUDPChannel.NONCE_LENGTH],
                encrypted_message[AsyncUDPChannel.NONCE_LENGTH:],
                b"")
        except:
            return encrypted_message

    def get_key(self) -> bytes:
        """Return the key used by the socket for encryption.

        :return: The encryption key of the server.
        """
        return self._key
