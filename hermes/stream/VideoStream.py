# -*- coding: utf-8 -*-
"""Implementation of a class that can be used to stream video using UDP.

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
import numpy as np
from typing import Optional, NoReturn, List, Union, Tuple
from hermes.messages.UDPMessage import UDPMessage
from hermes.network.AsyncUDPChannel import AsyncUDPChannel
import multiprocessing as mp
import time
from hermes.camera.CV2AsynchronousVideoCapture import \
    CV2AsynchronousVideoCapture
from threading import Thread
from hermes.stream.ImageManager import ImageManager
from hermes.stream.TopicManager import TopicManager
from hermes.stream.VideoTopic import VideoTopic


class VideoStream:
    """A class to manage video stream.

    This class inherit from Process to run the VideoStream on a different CPU
    core than parent process.

        Constants :
            EMITTER : Value that tell the VideoStream will send video stream.
            CONSUMER : Value that tell the VideoStream will receive video
            stream.

        Attributes :
            internal_pipe : Internal side of the pipe used for communication
            with the process.
            external_pipe : External side of the pipe used for communication
            with the process.
            im : The ImageManager used for video stream.
            role : Tell if the VideoStream is emitter or consumer.
            opened_topics : A list of VideoTopic waiting for completion.
            udp_socket : The UDPSocket used for sending or receiving data.
            socket_ip : The ip used to bind the socket.
            socket_port : The port used to bind the socket.
            encryption_in_transit : Define if the messages must be encrypted.
            max_queue_size : The max size of message queue.
            buffer_size : The max size of the received message buffer.
            _is_running : Tell if the process is running.
            key : The encryption key used to encrypt message. If no value is
            provided it will generate a new one.
            enable_multicast : Specify if the socket can use multicast.
            multicast_ttl : The TTL used for multicast.
            subs_list : A list of tuples containing ip address and port of
            subscribers.
            use_rcv_img_buffer : A bool that tell if received image are stored
            in a buffer or in a single variable.
            rcv_img_buffer : A buffer to store incoming image.
            from_source : Specify the source to use if needed.
            video_recorder : The CV2AsynchronousVideoCapture object used to
            stream if from_source is not None.
            _run_new_process : Specify if the CV2AsynchronousVideoCapture
            object must be run in a new process.
            async_msg_generation: Specify if the messages representing the
            image must be generated asynchronously.
            encoding: Define the encoding used to send images.
            encoding_param : Parameters used to encode image.
            See cv2.imencode for more details.
    """
    EMITTER = "emitter"
    CONSUMER = "consumer"

    def __init__(self, role: Optional[str] = EMITTER,
                 max_packet_size: Optional[int] = 60000,
                 socket_ip: Optional[str] = "127.0.0.1",
                 socket_port: Optional[int] = 50000,
                 encryption_in_transit: Optional[bool] = False,
                 max_queue_size: Optional[int] = 100,
                 buffer_size: Optional[int] = 65543,
                 key: Optional[Union[None, bytes]] = None,
                 enable_multicast: Optional[bool] = False,
                 multicast_ttl: Optional[int] = 2,
                 use_rcv_img_buffer: Optional[bool] = False,
                 from_source: Optional[Union[int, str]] = None,
                 run_new_process: Optional[bool] = True,
                 async_msg_generation: Optional[bool] = False,
                 encoding: Optional[int] = 0,
                 encoding_param: Optional[Union[dict, None]] = None):
        """Create a new VideoStream object with given parameter.

        :param role: Tell if the VideoStream is emitter or consumer.
        :param max_packet_size: The max size of a packet (in byte).
        :param socket_ip: The ip used to bind the socket.
        :param socket_port: The port used to bind the socket.
        :param encryption_in_transit: Define if the messages must be encrypted.
        :param max_queue_size: The max size of message queue.
        :param buffer_size: The max size of the received message buffer.
        :param key: The encryption key used to encrypt message. If no value is
        provided it will generate a new one.
        :param enable_multicast: Specify if the socket can use multicast.
        :param multicast_ttl: A list of tuples containing ip address and port
        of subscribers.
        :param use_rcv_img_buffer: A bool that tell if received image are
         stored in a buffer or in a single variable.
        :param from_source: Make the VideoStream stream from a source.
        :param run_new_process: Specify if the CV2AsynchronousVideoCapture
        object must be run in a new process.
        :param async_msg_generation: Specify if the messages representing the
        image must be generated asynchronously.
        :param encoding: Define the encoding used to send images.
        :param encoding_param: Parameters used to encode image.
        See cv2.imencode for more details.
        """
        self.internal_pipe, self.external_pipe = mp.Pipe()
        if role != VideoStream.EMITTER and role != VideoStream.CONSUMER:
            raise ValueError
        self.role = role
        self.im: ImageManager = \
            ImageManager(max_packet_size=max_packet_size,
                         async_msg_generation=async_msg_generation,
                         encoding=encoding,
                         encoding_param=encoding_param)
        self.opened_topics: List[VideoTopic] = []
        self.udp_socket: Union[AsyncUDPChannel, None] = None
        self.socket_ip = socket_ip
        self.socket_port = socket_port
        self.encryption_in_transit: bool = encryption_in_transit
        self.max_queue_size: int = max_queue_size
        self.buffer_size: int = buffer_size
        self.is_running: bool = False
        self.enable_multicast: bool = enable_multicast
        self.multicast_ttl: int = multicast_ttl
        if self.enable_multicast:
            raise NotImplementedError
        self.key: bytes = key
        self.subs_list: List[Tuple[str, int]] = []
        self.tm = TopicManager()
        self.use_rcv_img_buffer = use_rcv_img_buffer
        self.rcv_img_buffer: List[np.array] = []
        if use_rcv_img_buffer is False:
            self.rcv_img_buffer.append(None)
        self.from_source = from_source
        self.video_recorder: Union[None, CV2AsynchronousVideoCapture] = None
        self.run_new_process = run_new_process
        self.async_msg_generation = async_msg_generation
        self.encoding = encoding
        self.encoding_param = \
            encoding_param if encoding_param is not None else {}

    def start(self) -> VideoStream:
        """Start a new thread or a new process for asynchronous camera reading.

        :return: The current instance of the class.
        """
        if self.run_new_process is False:
            self._start()
        else:
            mp.Process(target=self._start).start()
        return self

    def _start(self) -> None:
        """Start the thread of the class."""
        Thread(target=self._work, args=()).start()

    def _refresh_image(self, new_image: np.array) -> None:
        """Change the value of current image by the value of new_image.

        :param new_image: The new image to send.
        """
        self.im.refresh_image(new_image)

    def refresh_image(self, new_image: np.array) -> None:
        """External call to _refresh_image.

        :param new_image: The new image to send.
        """
        if self.run_new_process is False:
            return self._refresh_image(new_image)
        self.external_pipe.send(
            (VideoStream._refresh_image, {"new_image": new_image}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _get_current_image(self) -> np.array:
        """Return the current value of current image.

        :return: The current value of current image.
        """
        return self.im.current_image

    def get_current_image(self) -> np.array:
        """External call to _get_current_image

        :return: The current value of current image.
        """
        if self.run_new_process is False:
            return self._get_current_image()
        self.external_pipe.send((VideoStream._get_current_image, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _work(self) -> NoReturn:
        """The main process of the VideoStream."""
        self._setup()
        self._loop()

    def _setup(self) -> None:
        """Initialization of the process."""
        must_listen = self.role == VideoStream.CONSUMER
        self.udp_socket = \
            AsyncUDPChannel(socket_ip=self.socket_ip,
                            socket_port=self.socket_port,
                            encryption_in_transit=self.encryption_in_transit,
                            max_queue_size=self.max_queue_size,
                            buffer_size=self.buffer_size,
                            key=self.key,
                            enable_multicast=self.enable_multicast,
                            multicast_ttl=self.multicast_ttl,
                            must_listen=must_listen)
        self.udp_socket.start()
        self.video_recorder = \
            None if self.from_source is None else CV2AsynchronousVideoCapture(
                src=self.from_source, run_new_process=False).start()
        self.im = self.im.start()
        self.is_running = True

    def _loop(self) -> NoReturn:
        """The main loop of the process."""
        max_topic = 2 ** (8 * UDPMessage.TOPIC_LENGTH)
        img_topic = 0
        while self.is_running:
            # Manage external call of class method when using Process class.
            if self.run_new_process and self.internal_pipe.poll():
                command = self.internal_pipe.recv()
                if type(command) is tuple:
                    self.internal_pipe.send(command[0](self, **command[1]))
            # Send image packets if the VideoStream object is emitter.
            if self.role == VideoStream.EMITTER:
                if self.video_recorder is not None:
                    self.im.refresh_image(self.video_recorder.read_frame())
                self.cast(img_topic)
                img_topic = (img_topic + 1) % max_topic
                if self.run_new_process:
                    VideoStream.delay(1)

            # Receive packets if the VideoStream object is consumer.
            if self.role == VideoStream.CONSUMER:
                while self.udp_socket.message_available():
                    msg = UDPMessage.from_bytes(self.udp_socket.pull()[0])
                    if type(msg) is not UDPMessage:
                        continue
                    self.tm.add_message(msg)
                if self.tm.in_waiting():
                    if self.use_rcv_img_buffer:
                        self.rcv_img_buffer.append(self.tm.pull())
                    else:
                        self.rcv_img_buffer[0] = self.tm.pull()

    def _stop(self) -> None:
        """Stop the process and its UDPSocket."""
        self.is_running = False
        self.udp_socket.stop()
        if self.im.async_msg_generation is True:
            self.im.stop()
        if self.video_recorder is not None:
            self.video_recorder.stop()

    def stop(self) -> None:
        """External call to _stop"""
        if self.run_new_process is False:
            return self._stop()
        self.external_pipe.send((VideoStream._stop, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _get_is_running(self) -> bool:
        """Return True if the process is currently running.

        :return: A bool that tell if the process is currently running.
        """
        return self.is_running

    def get_is_running(self):
        """External call to _get_is_running.

        :return: A bool that tell if the process is currently running.
        """
        if self.run_new_process is False:
            return self._get_is_running()
        self.external_pipe.send((VideoStream._get_is_running, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _add_subscriber(self, address_port) -> None:
        """Add a subscriber in the list of subscriber.

        :param address_port: A tuple containing the ip address and the port of
        the new subscriber.
        """
        self.subs_list.append(address_port)

    def add_subscriber(self, address_port) -> None:
        """External call to _add_subscriber.

        :param address_port: A tuple containing the ip address and the port of
        the new subscriber.
        """
        if self.run_new_process is False:
            return self._add_subscriber(address_port)
        self.external_pipe.send(
            (VideoStream._add_subscriber, {"address_port": address_port}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _get_subs_list(self) -> List[Tuple]:
        """Return the list of subscribers.

        :return: The list of subscribers.
        """
        return self.subs_list

    def get_subs_list(self) -> List[Tuple]:
        """External call to _get_subs_list.

        :return: The list of subscribers.
        """
        if self.run_new_process is False:
            return self._get_subs_list()
        self.external_pipe.send((VideoStream._get_subs_list, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _remove_subscriber(self, index: int) -> None:
        """Remove a subscriber from the list of subscriber.

        :param index: The index of the subscriber to remove.
        """
        self.subs_list.pop(index)

    def remove_subscriber(self, index: int) -> None:
        """External call to _remove_subscriber.

        :param index: The index of the subscriber to remove.
        """
        if self.run_new_process is False:
            return self._remove_subscriber(index)
        self.external_pipe.send(
            (VideoStream._remove_subscriber, {"index": index}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def cast(self, topic: int) -> None:
        """Send the current image using given topic number.

        :param topic: The number of the topic used to send the image.
        """
        if np.array_equiv(self.im.current_image, np.array([])) or len(
                self.subs_list) == 0:
            return
        for msg_to_send in self.im.get_messages(topic):
            for sub in self.subs_list:
                self.udp_socket.sendto(msg_to_send, sub)
            if self.run_new_process:
                VideoStream.delay(1)

    def _get_rcv_img(self) -> np.array:
        """Return the received image.

        :return: The received image.
        """
        if len(self.rcv_img_buffer) == 0:
            return None
        if self.use_rcv_img_buffer is False:
            return self.rcv_img_buffer[0]
        return self.rcv_img_buffer.pop(0)

    def get_rcv_img(self):
        """External call to _get_rcv_img.

        :return: The received image.
        """
        if self.run_new_process is False:
            return self._get_rcv_img()
        self.external_pipe.send((VideoStream._get_rcv_img, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _get_key(self) -> bytes:
        """Return the key used by the socket for encryption.

        :return: The encryption key of the server.
        """
        return self.udp_socket.get_key()

    def get_key(self) -> bytes:
        """External call to _get_key.

        :return: The encryption key of the server.
        """
        if self.run_new_process is False:
            return self._get_key()
        self.external_pipe.send((VideoStream._get_key, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    @staticmethod
    def delay(delay_ms: int) -> None:
        """Wait for delay_ms microseconds with better precision than sleep().

        :param delay_ms: The delay duration in ms
        """
        t_stop = np.int64(delay_ms * 10) + np.int64(
            np.float64(time.time()) * np.float64(10000000))
        while np.int64(
                np.float64(time.time()) * np.float64(10000000)) <= t_stop:
            pass
