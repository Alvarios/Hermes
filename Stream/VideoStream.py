# -*- coding: utf-8 -*-
"""Implementation of a class that can be use to stream video using UDP protocol.

This module provides a class that can be use to stream video using UDP protocol.
It is based on the UDPSocket to send and receive message asynchronously and UDPMessage
to ensure messages are read in correct order.
"""

import numpy as np
from typing import Optional, NoReturn, List, Union
import math
from Messages.UDPMessage import UDPMessage


class VideoStream:
    """A class to manage video streaming.

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
        """Create a new VideoStream with given parameters.

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
        self.current_image = new_image

    def split_image(self) -> List[bytes]:
        """Split current_image into bytes with a maximal length of max_packet_size.

        :return list_split_img: A list of bytes representing the current_image.
        """
        flat_img = self.current_image.flatten()
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
        return UDPMessage(msg_id=VideoStream.VIDEO_PACKET_ID, topic=topic, message_nb=VideoStream.NB_MSG_HEADER,
                          payload=nb_packet.to_bytes(VideoStream.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
                              VideoStream.TOTAL_BYTES_SIZE, 'little') + height.to_bytes(VideoStream.HEIGHT_SIZE,
                                                                                        'little') + length.to_bytes(
                              VideoStream.LENGTH_SIZE, 'little') + pixel_size.to_bytes(
                              VideoStream.SIZE_PIXEL_SIZE, 'little')).to_bytes()

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
            UDPMessage(msg_id=VideoStream.VIDEO_PACKET_ID, payload=e, topic=topic, message_nb=i + 1).to_bytes() for i, e
            in enumerate(img_split)]
        header = VideoStream.get_header_msg(topic, len(img_split), int(np.array(self.current_image.shape).prod()),
                                            self.current_image.shape[0], self.current_image.shape[1],
                                            self.get_pixel_size())
        to_return = [header] + img_messages
        # to_return = [header]
        return to_return


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
        if value < 1 or value >= pow(2, 8 * VideoStream.NB_PACKET_SIZE):
            raise ValueError
        self._nb_packet = value

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @total_bytes.setter
    def total_bytes(self, value: int) -> NoReturn:
        if value < 1 or value >= pow(2, 8 * VideoStream.TOTAL_BYTES_SIZE):
            raise ValueError
        self._total_bytes = value

    @property
    def pixel_size(self) -> int:
        return self._pixel_size

    @pixel_size.setter
    def pixel_size(self, value: int) -> NoReturn:
        if value < 1 or value >= pow(2, 8 * VideoStream.SIZE_PIXEL_SIZE):
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
        if int.from_bytes(new_message.message_nb, 'little') > self.nb_packet or int.from_bytes(new_message.message_nb,                                                                                               'little') <= 0:
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
        if self.total_bytes % self.pixel_size != 0 or self.total_bytes % self.height != 0 or self.total_bytes % self.length != 0:
            return None
        if self.pixel_size != 1:
            return np.concatenate([list(i.payload) for i in self.rcv_messages]).reshape((self.height, self.length,
                                                                                         self.pixel_size)).astype(
                np.uint8)
        return np.concatenate([list(i.payload) for i in self.rcv_messages]).reshape((self.height, self.length)).astype(
            np.uint8)

    @staticmethod
    def from_message(new_msg: UDPMessage):
        """Create a new VideoTopic from a UDPMessage.

        :param new_msg: The message used to create VideoTopic.
        :return new_topic: A new VideoTopic created from input message.
        """
        payload = new_msg.payload
        cursor_pos = 0
        nb_packet = int.from_bytes(payload[cursor_pos:cursor_pos + VideoStream.NB_PACKET_SIZE], 'little')
        cursor_pos += VideoStream.NB_PACKET_SIZE
        total_bytes = int.from_bytes(payload[cursor_pos:cursor_pos + VideoStream.TOTAL_BYTES_SIZE], 'little')
        cursor_pos += VideoStream.TOTAL_BYTES_SIZE
        height = int.from_bytes(payload[cursor_pos:cursor_pos + VideoStream.HEIGHT_SIZE], 'little')
        cursor_pos += VideoStream.HEIGHT_SIZE
        length = int.from_bytes(payload[cursor_pos:cursor_pos + VideoStream.LENGTH_SIZE], 'little')
        cursor_pos += VideoStream.LENGTH_SIZE
        pixel_size = int.from_bytes(payload[cursor_pos:cursor_pos + VideoStream.SIZE_PIXEL_SIZE], 'little')
        time_creation = int.from_bytes(new_msg.time_creation, 'little')
        return VideoTopic(nb_packet, total_bytes, height, length, pixel_size, time_creation)


if __name__ == "__main__":
    import cv2

    # vs = VideoStream(max_packet_size=UDPMessage.PAYLOAD_MAX_SIZE)
    vs = VideoStream(max_packet_size=UDPMessage.PAYLOAD_MAX_SIZE)
    cv2.namedWindow("preview")
    vc = cv2.VideoCapture(0)

    if vc.isOpened():  # try to get the first frame
        rval, frame = vc.read()
    else:
        rval = False

    while rval:
        rval, frame = vc.read()
        vs.refresh_image(frame)
        # print(vs.current_image.shape)
        # print(np.array(vs.current_image.shape).prod())
        msg = vs.get_messages(10)
        tmp = np.array([len(list(UDPMessage.from_bytes(i).payload)) for i in msg[1:]]).sum()

        topic = VideoTopic.from_message(UDPMessage.from_bytes(msg[0]))

        for i in msg[1:]:
            topic.add_message(UDPMessage.from_bytes(i))
        test_frame: np.array = topic.rebuild_img()

        # cv2.imshow("preview", frame)
        cv2.imshow("preview", test_frame)
        key = cv2.waitKey(20)
        if key == 27:  # exit on ESC
            break
    cv2.destroyWindow("preview")
