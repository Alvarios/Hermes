# -*- coding: utf-8 -*-
"""Implementation of a class that can be use to stream video using UDP protocol.

This module provides a class that can be use to stream video using UDP protocol.
It is based on the UDPSocket to send and receive message asynchronously and UDPMessage
to ensure messages are read in correct order.
"""

import numpy as np
from typing import Optional, NoReturn, List, Union, Tuple, Dict
import math
from Messages.UDPMessage import UDPMessage
from Sockets.UDPSocket import UDPSocket
import multiprocessing as mp
import time
from Polypheme.Eye import Eye


class VideoStream(mp.Process):
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
    """
    EMITTER = "emitter"
    CONSUMER = "consumer"

    def __init__(self, role: Optional[str] = EMITTER, max_packet_size: Optional[int] = 60000,
                 socket_ip: Optional[str] = "127.0.0.1",
                 socket_port: Optional[int] = 50000, encryption_in_transit: Optional[bool] = False,
                 max_queue_size: Optional[int] = 100, buffer_size: Optional[int] = 65543,
                 key: Optional[Union[None, bytes]] = None, enable_multicast: Optional[bool] = False,
                 multicast_ttl: Optional[int] = 2, use_rcv_img_buffer: Optional[bool] = False,
                 from_source: Optional[Union[int, str]] = None):
        """Create a new VideoStream object with given parameter and run the process.

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
        """
        super().__init__(target=self.process)
        self.internal_pipe, self.external_pipe = mp.Pipe()
        if role != VideoStream.EMITTER and role != VideoStream.CONSUMER:
            raise ValueError
        self.role = role
        self.im: ImageManager = ImageManager(max_packet_size)
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
        self.start()

    def _refresh_image(self, new_image: np.array) -> NoReturn:
        """Change the value of current image by the value of new_image.

        :param new_image: The new image to send.
        """
        self.im.refresh_image(new_image)

    def refresh_image(self, new_image: np.array) -> NoReturn:
        """External call to _refresh_image.

        :param new_image: The new image to send.
        """
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
        self.external_pipe.send((VideoStream._get_current_image, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def process(self) -> NoReturn:
        """The main process of the VideoStream."""
        self.setup()
        self.loop()

    def setup(self) -> NoReturn:
        """Initialization of the process."""
        self.is_running = True
        self.udp_socket = UDPSocket(socket_ip=self.socket_ip, socket_port=self.socket_port,
                                    encryption_in_transit=self.encryption_in_transit,
                                    max_queue_size=self.max_queue_size,
                                    buffer_size=self.buffer_size, key=self.key, enable_multicast=self.enable_multicast,
                                    multicast_ttl=self.multicast_ttl)
        self.udp_socket.start_socket()
        self.eye = None if self.from_source is None else Eye(src=self.from_source, run_new_process=False).start()

    def loop(self) -> NoReturn:
        """The main loop of the process."""
        max_topic = 2 ** (8 * UDPMessage.TOPIC_LENGTH)
        img_topic = 0
        while self.is_running:
            # Manage external call of class method.
            if self.internal_pipe.poll():
                command = self.internal_pipe.recv()
                if type(command) is tuple:
                    self.internal_pipe.send(command[0](self, **command[1]))
            # Send image packets if the VideoStream object is emitter.
            if self.role == VideoStream.EMITTER:
                if self.eye is not None:
                    self.im.refresh_image(self.eye.read())
                self.cast(img_topic)
                img_topic = (img_topic + 1) % max_topic
                VideoStream.delay(1)

            # Receive packets if the VideoStream object is consumer.
            if self.role == VideoStream.CONSUMER:
                while self.udp_socket.in_waiting():
                    msg = UDPMessage.from_bytes(self.udp_socket.pull()[0])
                    self.tm.add_message(msg)
                if self.tm.in_waiting():
                    if self.use_rcv_img_buffer:
                        self.rcv_img_buffer.append(self.tm.pull())
                    else:
                        self.rcv_img_buffer[0] = self.tm.pull()

    def _stop(self) -> NoReturn:
        """Stop the process and its UDPSocket."""
        self.is_running = False
        self.udp_socket.stop_socket()
        if self.eye is not None:
            self.eye.stop()

    def stop(self) -> NoReturn:
        """External call to _stop"""
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
            VIDEO_PACKET_ID : The message id used for udp packet.
            NB_MSG_HEADER : The message number of the header in the topic.

        Attributes :
            current_image : The current image to send.
            max_packet_size : The max size of a packet (in byte).

    """
    NB_PACKET_SIZE = 4
    TOTAL_BYTES_SIZE = 4
    HEIGHT_SIZE = 4
    LENGTH_SIZE = 4
    SIZE_PIXEL_SIZE = 1
    VIDEO_PACKET_ID = 210
    NB_MSG_HEADER = 0

    def __init__(self, max_packet_size: Optional[int] = 5000) -> None:
        """Create a new ImageManager with given parameters.

        :param max_packet_size: The max size of a packet (in byte).
        """
        self.current_image: np.array = np.array([])
        self.max_packet_size = max_packet_size

    def refresh_image(self, new_image: np.array) -> NoReturn:
        """Replace current_image by new_image.

        :param new_image:
        """
        if len(new_image.shape) > 3 or len(new_image.shape) < 2 or (
                len(new_image.shape) == 3 and new_image.shape[2] != 3):
            raise ValueError
        if new_image.dtype == np.uint8:
            self.current_image = new_image
        self.current_image = new_image.astype(np.uint8)

    def split_image(self) -> List[bytes]:
        """Split current_image into bytes with a maximal length of max_packet_size.

        :return list_split_img: A list of bytes representing the current_image.
        """
        flat_img = self.current_image.flatten().astype(np.uint8)
        return [bytes(flat_img[i * self.max_packet_size: self.max_packet_size + i * self.max_packet_size]) for i in
                range(math.ceil(np.array(self.current_image.shape).prod() / self.max_packet_size))]

    @staticmethod
    def get_header_msg(topic: int, nb_packet: int, total_bytes: int, height: int, length: int,
                       pixel_size: int) -> bytes:
        """Return a UDPMessage with image metadata.

        :param topic: The topic associated to the image.
        :param nb_packet: The total number of data packet that will be send.
        :param total_bytes: The total number of bytes of the image.
        :param height: The height of the image.
        :param length: The length of the image.
        :param pixel_size: The size of a pixel.
        :return header_msg: The UDPMessage containing image metadata.
        """
        return UDPMessage(msg_id=ImageManager.VIDEO_PACKET_ID, topic=topic, message_nb=ImageManager.NB_MSG_HEADER,
                          payload=nb_packet.to_bytes(ImageManager.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
                              ImageManager.TOTAL_BYTES_SIZE, 'little') + height.to_bytes(ImageManager.HEIGHT_SIZE,
                                                                                         'little') + length.to_bytes(
                              ImageManager.LENGTH_SIZE, 'little') + pixel_size.to_bytes(
                              ImageManager.SIZE_PIXEL_SIZE, 'little')).to_bytes()

    def get_pixel_size(self) -> int:
        """Return the size of a pixel.

        :return pixel_size: The size of a pixel.
        """
        return 3 if len(self.current_image.shape) == 3 else 1

    def get_messages(self, topic: int) -> List[bytes]:
        """Return a list of bytes representing the messages to send.

        :param topic: The topic associated to the image.
        :return messages: The list of bytes representing the messages to send.
        """
        img_split = self.split_image()
        img_messages = [
            UDPMessage(msg_id=ImageManager.VIDEO_PACKET_ID, payload=e, topic=topic, message_nb=i + 1).to_bytes() for
            i, e
            in enumerate(img_split)]
        header = ImageManager.get_header_msg(topic, len(img_split), int(np.array(self.current_image.shape).prod()),
                                             self.current_image.shape[0], self.current_image.shape[1],
                                             self.get_pixel_size())
        return [header] + img_messages


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

    """

    def __init__(self, nb_packet, total_bytes, height, length, pixel_size, time_creation) -> None:
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
        if self.total_bytes % self.pixel_size != 0 or self.total_bytes % self.height != 0 \
                or self.total_bytes % self.length != 0:
            return None
        if self.pixel_size != 1:
            return np.concatenate([np.frombuffer(i.payload, np.uint8) for i in self.rcv_messages]).reshape(
                (self.height, self.length, self.pixel_size)).astype(np.uint8)
            # return np.concatenate([list(i.payload) for i in self.rcv_messages]).reshape((self.height, self.length,
            #                                                                              self.pixel_size)).astype(
            #     np.uint8)
        return np.concatenate([np.frombuffer(i.payload, np.uint8) for i in self.rcv_messages]).reshape(
            (self.height, self.length)).astype(np.uint8)
        # python -m pytest -s -vv

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
        time_creation = int.from_bytes(new_msg.time_creation, 'little')
        return VideoTopic(nb_packet, total_bytes, height, length, pixel_size, time_creation)


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
            self.dead_letter_queue.append(new_message)

    def topic_exist(self, topic_num: int) -> bool:
        """Check if a given topic exist.

        :param topic_num: The id of the topic to check.

        :return topic_exist: A boolean that tell if the topic exist.
        """
        return topic_num in self.open_topic.keys()

    def process_dlq(self, new_topic: int) -> NoReturn:
        """Read messages in the dlq, add messages to an existing topic if possible and delete outdated ones.

        :param new_topic: The last topic created.
        """
        new_topic_time: int = self.open_topic[new_topic].time_creation
        remaining_messages = []
        for msg in self.dead_letter_queue:
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


if __name__ == "__main__":
    import cv2

    emitter_address_port = ('127.0.0.1', 50000)
    consumer_address_port = ('127.0.0.1', 50001)
    emitter = VideoStream(role=VideoStream.EMITTER, socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1], from_source=0)
    consumer = VideoStream(role=VideoStream.CONSUMER, socket_ip=consumer_address_port[0],
                           socket_port=consumer_address_port[1], use_rcv_img_buffer=False, max_queue_size=10000)
    while emitter.get_is_running() is False:
        pass
    while consumer.get_is_running() is False:
        pass
    emitter.add_subscriber(consumer_address_port)
    last_frame = None

    cv2.namedWindow("preview")
    cv2.imshow("preview", np.array(480 * [640 * [[255, 0, 0]]]).astype(np.uint8))
    while True:
        rcv_frame = consumer.get_rcv_img()
        if rcv_frame is not None:
            cv2.imshow("preview", rcv_frame)
        key = cv2.waitKey(20)
        if key == 27:  # exit on ESC
            break
    cv2.destroyWindow("preview")
    # emitter.stop()
    # consumer.stop()
