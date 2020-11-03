# -*- coding: utf-8 -*-
"""Implementation utils that can be use to stream video using UDP protocol.

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

import numpy as np
from typing import Optional, NoReturn, List, Union, Tuple, Dict
import math
from hermes.messages.UDPMessage import UDPMessage
from hermes.network.UDPSocket import UDPSocket
import multiprocessing as mp
import time
from hermes.polypheme.Eye import Eye
from threading import Thread
from itertools import chain
import cv2


class VideoStream:
    """A class to manage video streams.

    This class inherit from Process to run the VideoStream on a different CPU core than parent process.

        Constants :
            EMITTER : Value that tell the VideoStream will send video stream.
            CONSUMER : Value that tell the VideoStream will receive video stream.

        Attributes :
            internal_pipe : Internal side of the pipe used for communication with the process.
            external_pipe : External side of the pipe used for communication with the process.
            im : The ImageManager used for video stream.
            role : Tell if the VideoStream is emitter or consumer.
            opened_topics : A list of VideoTopic waiting for completion.
            udp_socket : The UDPSocket used for sending or receiving data.
            socket_ip : The ip used to bind the socket.
            socket_port : The port used to bind the socket.
            encryption_in_transit : Define if the messages must be encrypted.
            max_queue_size : The max size of message queue.
            buffer_size : The max size of the received message buffer.
            is_running : Tell if the process is running.
            key : The encryption key used to encrypt message. If no value is provided it will generate a new one.
            enable_multicast : Specify if the socket can use multicast.
            multicast_ttl : The TTL used for multicast.
            subs_list : A list of tuples containing ip address and port of subscribers.
            use_rcv_img_buffer : A bool that tell if received image are stored in a buffer or in a single variable.
            rcv_img_buffer : A buffer to store incoming image.
            from_source : Specify the source to use if needed.
            eye : The Eye object used to stream if from_source is not None.
            run_new_process : Specify if the Eye object must be run in a new process.
            async_msg_generation: Specify if the messages representing the image must be generated asynchronously.
            encoding: Define the encoding used to send images.
            encoding_param : Parameters used to encode image. See cv2.imencode for more details.
    """
    EMITTER = "emitter"
    CONSUMER = "consumer"

    def __init__(self, role: Optional[str] = EMITTER, max_packet_size: Optional[int] = 60000,
                 socket_ip: Optional[str] = "127.0.0.1",
                 socket_port: Optional[int] = 50000, encryption_in_transit: Optional[bool] = False,
                 max_queue_size: Optional[int] = 100, buffer_size: Optional[int] = 65543,
                 key: Optional[Union[None, bytes]] = None, enable_multicast: Optional[bool] = False,
                 multicast_ttl: Optional[int] = 2, use_rcv_img_buffer: Optional[bool] = False,
                 from_source: Optional[Union[int, str]] = None, run_new_process: Optional[bool] = True,
                 async_msg_generation: Optional[bool] = False, encoding: Optional[int] = 0,
                 encoding_param: Optional[Union[dict, None]] = None):
        """Create a new VideoStream object with given parameter.

        :param role: Tell if the VideoStream is emitter or consumer.
        :param max_packet_size: The max size of a packet (in byte).
        :param socket_ip: The ip used to bind the socket.
        :param socket_port: The port used to bind the socket.
        :param encryption_in_transit: Define if the messages must be encrypted.
        :param max_queue_size: The max size of message queue.
        :param buffer_size: The max size of the received message buffer.
        :param key: The encryption key used to encrypt message. If no value is provided it will generate a new one.
        :param enable_multicast: Specify if the socket can use multicast.
        :param multicast_ttl: A list of tuples containing ip address and port of subscribers.
        :param use_rcv_img_buffer: A bool that tell if received image are stored in a buffer or in a single variable.
        :param from_source: Make the VideoStream stream from a source.
        :param run_new_process: Specify if the Eye object must be run in a new process.
        :param async_msg_generation: Specify if the messages representing the image must be generated asynchronously.
        :param encoding: Define the encoding used to send images.
        :param encoding_param: Parameters used to encode image. See cv2.imencode for more details.
        """
        self.internal_pipe, self.external_pipe = mp.Pipe()
        if role != VideoStream.EMITTER and role != VideoStream.CONSUMER:
            raise ValueError
        self.role = role
        self.im: ImageManager = ImageManager(max_packet_size=max_packet_size, async_msg_generation=async_msg_generation,
                                             encoding=encoding, encoding_param=encoding_param)
        self.opened_topics: List[VideoTopic] = []
        self.udp_socket: Union[UDPSocket, None] = None
        self.socket_ip = socket_ip
        self.socket_port = socket_port
        self.encryption_in_transit: bool = encryption_in_transit
        self.max_queue_size: int = max_queue_size
        self.buffer_size: int = buffer_size
        self.is_running: bool = False
        self.enable_multicast: bool = enable_multicast
        self.multicast_ttl: int = multicast_ttl
        self.key: bytes = key
        self.subs_list: List[Tuple[str, int]] = []
        self.tm = TopicManager()
        self.use_rcv_img_buffer = use_rcv_img_buffer
        self.rcv_img_buffer: List[np.array] = []
        if use_rcv_img_buffer is False:
            self.rcv_img_buffer.append(None)
        self.from_source = from_source
        self.eye: Union[None, Eye] = None
        self.run_new_process = run_new_process
        self.async_msg_generation = async_msg_generation
        self.encoding = encoding
        self.encoding_param = encoding_param if encoding_param is not None else {}

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
        Thread(target=self._work, args=()).start()

    def _refresh_image(self, new_image: np.array) -> NoReturn:
        """Change the value of current image by the value of new_image.

        :param new_image: The new image to send.
        """
        self.im.refresh_image(new_image)

    def refresh_image(self, new_image: np.array) -> NoReturn:
        """External call to _refresh_image.

        :param new_image: The new image to send.
        """
        if self.run_new_process is False:
            return self._refresh_image(new_image)
        self.external_pipe.send((VideoStream._refresh_image, {"new_image": new_image}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _get_current_image(self) -> np.array:
        """Return the current value of current image.

        :return current_image: The current value of current image.
        """
        return self.im.current_image

    def get_current_image(self) -> np.array:
        """External call to _get_current_image

        :return current_image: The current value of current image.
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

    def _setup(self) -> NoReturn:
        """Initialization of the process."""
        self.is_running = True
        must_listen = self.role == VideoStream.CONSUMER
        self.udp_socket = UDPSocket(socket_ip=self.socket_ip, socket_port=self.socket_port,
                                    encryption_in_transit=self.encryption_in_transit,
                                    max_queue_size=self.max_queue_size,
                                    buffer_size=self.buffer_size, key=self.key, enable_multicast=self.enable_multicast,
                                    multicast_ttl=self.multicast_ttl, must_listen=must_listen)
        self.udp_socket.start()
        self.eye = None if self.from_source is None else Eye(src=self.from_source, run_new_process=False).start()
        self.im = self.im.start()

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
                if self.eye is not None:
                    self.im.refresh_image(self.eye.read())
                self.cast(img_topic)
                img_topic = (img_topic + 1) % max_topic
                if self.run_new_process:
                    VideoStream.delay(1)

            # Receive packets if the VideoStream object is consumer.
            if self.role == VideoStream.CONSUMER:
                while self.udp_socket.in_waiting():
                    msg = UDPMessage.from_bytes(self.udp_socket.pull()[0])
                    if type(msg) is not UDPMessage:
                        continue
                    self.tm.add_message(msg)
                if self.tm.in_waiting():
                    if self.use_rcv_img_buffer:
                        self.rcv_img_buffer.append(self.tm.pull())
                    else:
                        self.rcv_img_buffer[0] = self.tm.pull()

    def _stop(self) -> NoReturn:
        """Stop the process and its UDPSocket."""
        self.is_running = False
        self.udp_socket.stop()
        if self.im.async_msg_generation is True:
            self.im.stop()
        if self.eye is not None:
            self.eye.stop()

    def stop(self) -> NoReturn:
        """External call to _stop"""
        if self.run_new_process is False:
            return self._stop()
        self.external_pipe.send((VideoStream._stop, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _get_is_running(self) -> bool:
        """Return True if the process is currently running.

        :return is_running: A bool that tell if the process is currently running.
        """
        return self.is_running

    def get_is_running(self):
        """External call to _get_is_running.

        :return is_running: A bool that tell if the process is currently running.
        """
        if self.run_new_process is False:
            return self._get_is_running()
        self.external_pipe.send((VideoStream._get_is_running, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _add_subscriber(self, address_port) -> NoReturn:
        """Add a subscriber in the list of subscriber.

        :param address_port: A tuple containing the ip address and the port of the new subscriber.
        """
        self.subs_list.append(address_port)

    def add_subscriber(self, address_port) -> NoReturn:
        """External call to _add_subscriber.

        :param address_port: A tuple containing the ip address and the port of the new subscriber.
        """
        if self.run_new_process is False:
            return self._add_subscriber(address_port)
        self.external_pipe.send((VideoStream._add_subscriber, {"address_port": address_port}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _get_subs_list(self) -> List[Tuple]:
        """Return the list of subscribers.

        :return subs_list: The list of subscribers.
        """
        return self.subs_list

    def get_subs_list(self) -> List[Tuple]:
        """External call to _get_subs_list.

        :return subs_list: The list of subscribers.
        """
        if self.run_new_process is False:
            return self._get_subs_list()
        self.external_pipe.send((VideoStream._get_subs_list, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _remove_subscriber(self, index: int) -> NoReturn:
        """Remove a subscriber from the list of subscriber.

        :param index: The index of the subscriber to remove.
        """
        self.subs_list.pop(index)

    def remove_subscriber(self, index: int) -> NoReturn:
        """External call to _remove_subscriber.

        :param index: The index of the subscriber to remove.
        """
        if self.run_new_process is False:
            return self._remove_subscriber(index)
        self.external_pipe.send((VideoStream._remove_subscriber, {"index": index}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def cast(self, topic: int) -> NoReturn:
        """Send the current image using given topic number.

        :param topic: The number of the topic used to send the image.
        """
        if np.array_equiv(self.im.current_image, np.array([])) or len(self.subs_list) == 0:
            return
        for msg_to_send in self.im.get_messages(topic):
            for sub in self.subs_list:
                self.udp_socket.sendto(msg_to_send, sub)
            if self.run_new_process:
                VideoStream.delay(1)

    def _get_rcv_img(self) -> np.array:
        """Return the received image.

        :return rcv_img: The received image.
        """
        if len(self.rcv_img_buffer) == 0:
            return None
        if self.use_rcv_img_buffer is False:
            return self.rcv_img_buffer[0]
        return self.rcv_img_buffer.pop(0)

    def get_rcv_img(self):
        """External call to _get_rcv_img.

        :return rcv_img: The received image.
        """
        if self.run_new_process is False:
            return self.get_rcv_img()
        self.external_pipe.send((VideoStream._get_rcv_img, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    @staticmethod
    def delay(delay_ms: int) -> NoReturn:
        """Wait for delay_ms microseconds.

        :param delay_ms: The delay duration in ms
        """
        t_stop = np.int64(delay_ms * 10) + np.int64(np.float64(time.time()) * np.float64(10000000))
        while np.int64(np.float64(time.time()) * np.float64(10000000)) <= t_stop:
            pass


class ImageManager:
    """A class to manage image to send.

        Constants :
            NB_PACKET_SIZE : The number of bytes to store the number of packet.
            TOTAL_BYTES_SIZE : The number of bytes to store the total size of incoming image (in bytes).
            HEIGHT_SIZE : The number of bytes to store height of the image.
            LENGTH_SIZE : The number of bytes to store length of the image.
            SIZE_PIXEL_SIZE : The number of bytes to store the size of a pixel (in bytes).
            ENCODING_SIZE : The number of bytes to encoding.
            VIDEO_PACKET_ID : The message id used for udp packet.
            NB_MSG_HEADER : The message number of the header in the topic.
            ENCODING_DICT : A dictionary containing available encoding method and their corresponding code.

        Attributes :
            current_image : The current image to send.
            _new_image : Specify if a new message has been received (used for async message processing).
            _topic : A topic used for async message processing.
            max_packet_size : The max size of a packet (in byte).
            async_msg_generation : Specify if the messages representing the image must be generated asynchronously.
            messages : The asynchronously generated messages.
            is_running : Specify if the associated Thread is running (used for async message processing).
            encoding : Define the encoding used to send images.
            encoding_param: Parameters used to encode image. See cv2.imencode for more details.
                Example for jpg encoding : encoding_param = {"params": [int(cv2.IMWRITE_JPEG_QUALITY), 50]} where 50
                is the quality of the resulting image.

    """
    NB_PACKET_SIZE = 4
    TOTAL_BYTES_SIZE = 4
    HEIGHT_SIZE = 4
    LENGTH_SIZE = 4
    SIZE_PIXEL_SIZE = 1
    ENCODING_SIZE = 1
    VIDEO_PACKET_ID = 210
    NB_MSG_HEADER = 0
    ENCODING_DICT = {1: ".jpg"}

    def __init__(self, max_packet_size: Optional[int] = 5000, async_msg_generation: Optional[bool] = False,
                 encoding: Optional[int] = 0, encoding_param: Optional[Union[dict, None]] = None) -> None:
        """Create a new ImageManager with given parameters.

        :param max_packet_size: The max size of a packet (in byte).
        :param async_msg_generation: Specify if the messages representing the image must be generated asynchronously.
        :param encoding: Define the encoding used to send images.
        :param encoding_param: Parameters used to encode image. See cv2.imencode for more details.
        """
        self.current_image: np.array = np.array([])
        self._new_image = False
        self._topic = 0
        self.max_packet_size: int = max_packet_size
        self.async_msg_generation = async_msg_generation
        self.messages: iter = iter([])
        self.is_running = False
        self.encoding = encoding
        self.encoding_param = encoding_param if encoding_param is not None else {}

    def start(self):
        """Start a new thread if async_msg_generation is True.

        :return image_manager: The current instance of the class.
        """
        if self.async_msg_generation:
            Thread(target=self._work, args=()).start()
        return self

    def _work(self):
        """Execute the setup and the main loop of the class."""
        self._setup()
        self._loop()

    def _setup(self):
        """Setup function of the class."""
        self.is_running = True
        self.messages = iter([])

    def _loop(self):
        """Main loop of the class"""
        while self.is_running and self.async_msg_generation:
            if self._new_image is True:
                self.messages = self.get_messages(self._topic, force=True)
                self._topic += 1
                self._new_image = False
            else:
                time.sleep(.001)

    def stop(self):
        """Stop the thread of the instance of the class."""
        self.is_running = False

    def refresh_image(self, new_image: np.array) -> NoReturn:
        """Replace current_image by new_image.

        :param new_image: The new image to process.
        """
        if self._new_image and self.async_msg_generation:
            return
        if len(new_image.shape) > 3 or len(new_image.shape) < 2 or (
                len(new_image.shape) == 3 and new_image.shape[2] != 3):
            raise ValueError
        if new_image.dtype == np.uint8:
            self.current_image = new_image
        else:
            self.current_image = new_image.astype(np.uint8)
        self._new_image = True

    def split_image(self) -> map:
        """Split current_image into bytes with a maximal length of max_packet_size.

        :return split_img: An iterator containing bytes representing the current_image.
        """
        if self.encoding == 0:
            return map(lambda x: x.tobytes(), np.array_split(self.current_image.flatten(), math.ceil(np.array(
                self.current_image.shape).prod() / self.max_packet_size)))
        if self.encoding in ImageManager.ENCODING_DICT.keys():
            result, img = cv2.imencode(ImageManager.ENCODING_DICT[self.encoding], self.current_image,
                                       **self.encoding_param)
            return map(lambda x: x.tobytes(), np.array_split(img.flatten(), math.ceil(np.array(
                self.current_image.shape).prod() / self.max_packet_size)))

    @staticmethod
    def get_header_msg(topic: int, nb_packet: int, total_bytes: int, height: int, length: int,
                       pixel_size: int, encoding: Optional[int] = 0) -> bytes:
        """Return a UDPMessage with image metadata.

        :param topic: The topic associated to the image.
        :param nb_packet: The total number of data packet that will be send.
        :param total_bytes: The total number of bytes of the image.
        :param height: The height of the image.
        :param length: The length of the image.
        :param pixel_size: The size of a pixel.
        :param encoding: The encoding of the pixel (default 0 = None).
        :return header_msg: The UDPMessage containing image metadata.
        """
        return UDPMessage(msg_id=ImageManager.VIDEO_PACKET_ID, topic=topic, message_nb=ImageManager.NB_MSG_HEADER,
                          payload=nb_packet.to_bytes(ImageManager.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
                              ImageManager.TOTAL_BYTES_SIZE, 'little') + height.to_bytes(ImageManager.HEIGHT_SIZE,
                                                                                         'little') + length.to_bytes(
                              ImageManager.LENGTH_SIZE, 'little') + pixel_size.to_bytes(
                              ImageManager.SIZE_PIXEL_SIZE, 'little') + encoding.to_bytes(
                              ImageManager.ENCODING_SIZE, 'little')).to_bytes()

    def get_pixel_size(self) -> int:
        """Return the size of a pixel.

        :return pixel_size: The size of a pixel.
        """
        return 3 if len(self.current_image.shape) == 3 else 1

    def get_messages(self, topic: int, force: Optional[bool] = False) -> iter:
        """Return a list of bytes representing the messages to send.

        :param topic: The topic associated to the image.
        :param force: Specify if tje messages must be re-computed.
        :return messages: An iterator containing the the messages to send as bytes.
        """
        if self.async_msg_generation and (force is False):
            return self.messages
        img_split = self.split_image()
        to_msg = lambda enum: UDPMessage(msg_id=ImageManager.VIDEO_PACKET_ID, payload=enum[1], topic=topic,
                                         message_nb=enum[0] + 1).to_bytes()
        img_messages = map(to_msg, enumerate(img_split))
        header = ImageManager.get_header_msg(topic, math.ceil(np.array(
            self.current_image.shape).prod() / self.max_packet_size), int(np.array(self.current_image.shape).prod()),
                                             self.current_image.shape[0], self.current_image.shape[1],
                                             self.get_pixel_size(), encoding=self.encoding)
        return chain([header], img_messages)


class VideoTopic:
    """A class designed rebuild an image received in many packets.

        Attributes :
            nb_packet : The number of expected packets.
            total_bytes : The expected total size of the image.
            height : The height of the image.
            length : The length of the image.
            pixel_size : The size of pixel in bytes.
            time_creation : The time of creation of the topic.
            rcv_messages : The list of received packets.
            rcv_error : A flag that tell if a reception error has been detected.
            count_rcv_msg : Count the number of message that have been received.
            encoding : Encoding used for image transmission.

    """

    def __init__(self, nb_packet: int, total_bytes: int, height: int, length: int, pixel_size: int, time_creation: int,
                 encoding: Optional[int] = 0) -> None:
        """Create a new VideoTopic object.

        :param nb_packet: The number of expected packets.
        :param total_bytes: The expected total size of the image.
        :param height: The height of the image.
        :param length: The length of the image.
        :param pixel_size: The size of pixel in bytes.
        :param time_creation: The time of creation of the topic.
        """
        self.nb_packet: int = nb_packet
        self.total_bytes: int = total_bytes
        self.height = height
        self.length = length
        self.pixel_size: int = pixel_size
        self.time_creation: int = time_creation
        self.rcv_messages: List[Union[UDPMessage, None]] = [None for i in range(nb_packet)]
        self.rcv_error = False
        self.count_rcv_msg = 0
        self.encoding = encoding

    @property
    def nb_packet(self) -> int:
        return self._nb_packet

    @nb_packet.setter
    def nb_packet(self, value: int) -> NoReturn:
        if value < 1 or value >= pow(2, 8 * ImageManager.NB_PACKET_SIZE):
            raise ValueError
        self._nb_packet = value

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @total_bytes.setter
    def total_bytes(self, value: int) -> NoReturn:
        if value < 1 or value >= pow(2, 8 * ImageManager.TOTAL_BYTES_SIZE):
            raise ValueError
        self._total_bytes = value

    @property
    def pixel_size(self) -> int:
        return self._pixel_size

    @pixel_size.setter
    def pixel_size(self, value: int) -> NoReturn:
        if value < 1 or value >= pow(2, 8 * ImageManager.SIZE_PIXEL_SIZE):
            raise ValueError
        self._pixel_size = value

    @property
    def time_creation(self):
        return self._time_creation

    @time_creation.setter
    def time_creation(self, value):
        if value < 0 or value >= pow(2, 8 * UDPMessage.TIME_CREATION_LENGTH):
            raise ValueError
        self._time_creation = value

    def add_message(self, new_message: UDPMessage) -> NoReturn:
        """Add a message to the topic.

        The position of the message in rcv_message list will depend on message_nb (start at 1).

        :param new_message: The message to add to the topic.
        """
        if type(new_message) is not UDPMessage:
            return
        self.count_rcv_msg += 1
        if int.from_bytes(new_message.message_nb, 'little') > self.nb_packet or int.from_bytes(new_message.message_nb,
                                                                                               'little') <= 0:
            self.rcv_error = True
            return
        self.rcv_messages[int.from_bytes(new_message.message_nb, 'little') - 1] = new_message
        if new_message.check_crc() is False:
            self.rcv_error = True

    def all_msg_received(self) -> bool:
        """Return True if all messages of the topic have been received else False.

        :return all_msg_received: A bool that tell if all messages have been received.
        """
        return self.count_rcv_msg == self.nb_packet

    def total_bytes_correct(self) -> bool:
        """Check if the expected number of bytes is equal to the received number of bytes.

        :return total_bytes_correct: A bool that tell if a correct number of bytes have been received.
        """
        if self.all_msg_received():
            return np.array(
                [len(i.payload) if i is not None else 0 for i in self.rcv_messages]).sum() == self.total_bytes
        return False

    def rebuild_img(self) -> np.array:
        """Return an image as numpy array if all required messages have been received and nor error is detected.

        :return image: The image encoded in the received messages. None if an error is detected.
        """
        if self.encoding != 0:
            try:
                encoded_img = np.concatenate([np.frombuffer(i.payload, np.uint8) for i in self.rcv_messages])
                encoded_img = encoded_img.reshape(len(encoded_img), 1)
                return cv2.imdecode(encoded_img, 1)
            except:
                return None

        if self.total_bytes % self.pixel_size != 0 or self.total_bytes % self.height != 0 \
                or self.total_bytes % self.length != 0:
            return None
        if self.pixel_size != 1:
            try:
                return np.concatenate([np.frombuffer(i.payload, np.uint8) for i in self.rcv_messages]).reshape(
                    (self.height, self.length, self.pixel_size)).astype(np.uint8)
            except:
                return None
        return np.concatenate([np.frombuffer(i.payload, np.uint8) for i in self.rcv_messages]).reshape(
            (self.height, self.length)).astype(np.uint8)

    @staticmethod
    def from_message(new_msg: UDPMessage):
        """Create a new VideoTopic from a UDPMessage.

        :param new_msg: The message used to create VideoTopic.
        :return new_topic: A new VideoTopic created from input message.
        """
        payload = new_msg.payload
        cursor_pos = 0
        nb_packet = int.from_bytes(payload[cursor_pos:cursor_pos + ImageManager.NB_PACKET_SIZE], 'little')
        cursor_pos += ImageManager.NB_PACKET_SIZE
        total_bytes = int.from_bytes(payload[cursor_pos:cursor_pos + ImageManager.TOTAL_BYTES_SIZE], 'little')
        cursor_pos += ImageManager.TOTAL_BYTES_SIZE
        height = int.from_bytes(payload[cursor_pos:cursor_pos + ImageManager.HEIGHT_SIZE], 'little')
        cursor_pos += ImageManager.HEIGHT_SIZE
        length = int.from_bytes(payload[cursor_pos:cursor_pos + ImageManager.LENGTH_SIZE], 'little')
        cursor_pos += ImageManager.LENGTH_SIZE
        pixel_size = int.from_bytes(payload[cursor_pos:cursor_pos + ImageManager.SIZE_PIXEL_SIZE], 'little')
        cursor_pos += ImageManager.SIZE_PIXEL_SIZE
        encoding = int.from_bytes(payload[cursor_pos:cursor_pos + ImageManager.ENCODING_SIZE], 'little')
        time_creation = int.from_bytes(new_msg.time_creation, 'little')
        return VideoTopic(nb_packet, total_bytes, height, length, pixel_size, time_creation, encoding=encoding)


class TopicManager:
    """A class designed to manage the incoming messages in order to rebuild images.

        Attributes :
            open_topic : A dictionary of VideoTopic representing current open topic.
            img_queue : A list of images waiting to be pulled.
            dead_letter_queue : A list of added data messages with no existing topic.

    """

    def __init__(self) -> None:
        """Create a new TopicManager instance."""
        self.open_topic: Dict[int, VideoTopic] = {}
        self.img_queue: List[np.array] = []
        self.dead_letter_queue: List[UDPMessage] = []

    def in_waiting(self) -> bool:
        """Return True if an image is waiting in img_queue.

        :return in_waiting: A boolean that tell if an image is waiting in img_queue.
        """
        return len(self.img_queue) > 0

    def add_message(self, new_message: UDPMessage) -> NoReturn:
        """Read incoming message and do the needed action associated to the message.

        This function contains three cases, the first one is when the added message requires the creation of a new
        topic. The function will create the topic if it is possible and then will check the dead letter queue to
        check if there are messages associated to this new topic. The outdated messages in the dlq will be deleted at
        this step.

        The second case is when a data message is received. If the associated topic exists, the message will be added to
        this topic. If the topic is completed with the incoming message, the image will be rebuild and
        added to img_queue.

        The third case is when the message cannot be processed now. If it is the case it will be put in the dlq to be
        processed later.

        :param new_message: The message to process.
        """
        topic = int.from_bytes(new_message.topic, 'little')
        msg_nb = int.from_bytes(new_message.message_nb, 'little')
        if msg_nb == 0 and (topic not in self.open_topic.keys()):
            self.open_topic[topic] = VideoTopic.from_message(new_message)
            self.process_dlq(topic)
        elif topic in self.open_topic.keys() and self.open_topic[topic].nb_packet >= msg_nb:
            self.open_topic[topic].add_message(new_message)
            self.check_topic(topic)
        else:
            self.put_dlq(new_message)

    def topic_exist(self, topic_num: int) -> bool:
        """Check if a given topic exist.

        :param topic_num: The id of the topic to check.

        :return topic_exist: A boolean that tell if the topic exist.
        """
        return topic_num in self.open_topic.keys()

    def put_dlq(self, msg: UDPMessage) -> NoReturn:
        """Put a new message in the dead letter queue."""
        if type(msg) is UDPMessage:
            self.dead_letter_queue.append(msg)

    def process_dlq(self, new_topic: int) -> NoReturn:
        """Read messages in the dlq, add messages to an existing topic if possible and delete outdated ones.

        :param new_topic: The last topic created.
        """
        new_topic_time: int = self.open_topic[new_topic].time_creation
        remaining_messages = []
        for msg in self.dead_letter_queue:
            if type(msg) is not UDPMessage:
                continue
            if int.from_bytes(msg.topic, 'little') in self.open_topic.keys():
                self.add_message(msg)
            elif int.from_bytes(msg.time_creation, 'little') >= new_topic_time:
                remaining_messages.append(remaining_messages)
        self.dead_letter_queue = remaining_messages

    def check_topic(self, topic_num) -> NoReturn:
        """Rebuild image and add it to the queue nd delete old topic if needed.

        :param topic_num: The topic to check.
        """
        keep_open = {}
        if self.open_topic[topic_num].all_msg_received():
            time_topic = self.open_topic[topic_num].time_creation
            new_img = (self.open_topic.pop(topic_num)).rebuild_img()
            if new_img is not None:
                self.img_queue.append(new_img)
            for topic_key in self.open_topic.keys():
                if self.open_topic[topic_key].time_creation >= time_topic:
                    keep_open[topic_key] = self.open_topic[topic_key]
            self.open_topic = keep_open

    def pull(self) -> np.array:
        """Return the first image of img_queue if it is available.

        :return new_img: The first image of the queue.
        """
        if self.in_waiting():
            return self.img_queue.pop(0)
