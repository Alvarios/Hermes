# -*- coding: utf-8 -*-
"""Implementation of a class that can be use to stream video using UDP protocol.

This module provides a class that can be use to stream video using UDP protocol.
It is based on the UDPSocket to send and receive message asynchronously and UDPMessage
to ensure messages are read in correct order.
"""

import numpy as np
from typing import Optional, NoReturn, List
import math
from Messages.UDPMessage import UDPMessage


class VideoStream:
    """A class to manage video streaming.

        Constants :
            NB_PACKET_SIZE : The number of bytes to store the number of packet.
            TOTAL_BYTES_SIZE : The number of bytes to store the total size of incoming image (in bytes).
            SIZE_PIXEL_SIZE : The number of bytes to store the size of a pixel (in bytes).
            VIDEO_PACKET_ID : The message id used for udp packet.
            NB_MSG_HEADER : The message number of the header in the topic.

        Attributes :
            current_image : The current image to send.
            max_packet_size : The max size of a packet (in byte).

    """
    NB_PACKET_SIZE = 4
    TOTAL_BYTES_SIZE = 4
    SIZE_PIXEL_SIZE = 1
    VIDEO_PACKET_ID = 210
    NB_MSG_HEADER = 0

    def __init__(self, max_packet_size: Optional[int] = 5000) -> None:
        self.current_image: np.array = np.array([])
        self.max_packet_size = max_packet_size

    def refresh_image(self, new_image: np.array) -> NoReturn:
        if len(new_image.shape) > 2 or (len(new_image.shape) == 2 and new_image.shape[1] != 3):
            raise ValueError
        self.current_image = new_image

    def split_image(self) -> List[bytes]:
        flat_img = list(self.current_image.flatten())
        return [bytes(flat_img[i * self.max_packet_size: self.max_packet_size + i * self.max_packet_size]) for i in
                range(math.ceil(np.array(self.current_image.shape).prod() / self.max_packet_size))]

    @staticmethod
    def get_header_msg(topic, nb_packet, total_bytes, pixel_size) -> bytes:
        return UDPMessage(msg_id=VideoStream.VIDEO_PACKET_ID, topic=topic, message_nb=VideoStream.NB_MSG_HEADER,
                          payload=nb_packet.to_bytes(VideoStream.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
                              VideoStream.TOTAL_BYTES_SIZE, 'little') + pixel_size.to_bytes(
                              VideoStream.SIZE_PIXEL_SIZE, 'little')).to_bytes()

    def get_pixel_size(self) -> int:
        return 3 if len(self.current_image.shape) == 2 else 1

    def get_messages(self, topic: int) -> List[bytes]:
        img_split = self.split_image()
        img_messages = [
            UDPMessage(msg_id=VideoStream.VIDEO_PACKET_ID, payload=e, topic=topic, message_nb=i + 1).to_bytes() for i, e
            in enumerate(img_split)]
        header = VideoStream.get_header_msg(topic, len(img_split), int(np.array(self.current_image.shape).prod()),
                                            self.get_pixel_size())
        to_return = [header] + img_messages
        return to_return


class VideoTopic:

    def __init__(self, nb_packet, total_bytes, pixel_size, time_creation) -> None:
        self.nb_packet: int = nb_packet
        self.total_bytes: int = total_bytes
        self.pixel_size: int = pixel_size
        self.time_creation: int = time_creation

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
