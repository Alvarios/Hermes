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
        self.current_image: np.array = np.array([])
        self.max_packet_size = max_packet_size

    def refresh_image(self, new_image: np.array) -> NoReturn:
        if len(new_image.shape) > 3 or len(new_image.shape) < 2 or (
                len(new_image.shape) == 3 and new_image.shape[2] != 3):
            raise ValueError
        self.current_image = new_image

    def split_image(self) -> List[bytes]:
        flat_img = list(self.current_image.flatten())
        return [bytes(flat_img[i * self.max_packet_size: self.max_packet_size + i * self.max_packet_size]) for i in
                range(math.ceil(np.array(self.current_image.shape).prod() / self.max_packet_size))]

    @staticmethod
    def get_header_msg(topic: int, nb_packet: int, total_bytes: int, height: int, length: int,
                       pixel_size: int) -> bytes:
        return UDPMessage(msg_id=VideoStream.VIDEO_PACKET_ID, topic=topic, message_nb=VideoStream.NB_MSG_HEADER,
                          payload=nb_packet.to_bytes(VideoStream.NB_PACKET_SIZE, 'little') + total_bytes.to_bytes(
                              VideoStream.TOTAL_BYTES_SIZE, 'little') + height.to_bytes(VideoStream.HEIGHT_SIZE,
                                                                                        'little') + length.to_bytes(
                              VideoStream.LENGTH_SIZE, 'little') + pixel_size.to_bytes(
                              VideoStream.SIZE_PIXEL_SIZE, 'little')).to_bytes()

    def get_pixel_size(self) -> int:
        return 3 if len(self.current_image.shape) == 3 else 1

    def get_messages(self, topic: int) -> List[bytes]:
        img_split = self.split_image()
        img_messages = [
            UDPMessage(msg_id=VideoStream.VIDEO_PACKET_ID, payload=e, topic=topic, message_nb=i + 1).to_bytes() for i, e
            in enumerate(img_split)]
        header = VideoStream.get_header_msg(topic, len(img_split), int(np.array(self.current_image.shape).prod()),
                                            self.current_image.shape[0], self.current_image.shape[1],
                                            self.get_pixel_size())
        to_return = [header] + img_messages
        return to_return


class VideoTopic:
    """A class designed rebuild an image received in many packets.

        Attributes :
            nb_packet : The number of expected packets.
            total_bytes : The expected total size of the image.
            pixel_size : The size of pixel in bytes.
            time_creation : The time of creation of the topic.
            rcv_messages : The list of received packets.
            rcv_error : A flag that tell if a reception error has been detected.
            count_rcv_msg : Count the number of message that have been received

    """

    def __init__(self, nb_packet, total_bytes, height, length, pixel_size, time_creation) -> None:
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

    def add_message(self, new_message: UDPMessage):
        self.count_rcv_msg += 1
        if int.from_bytes(new_message.message_nb, 'little') > self.nb_packet or int.from_bytes(new_message.message_nb,
                                                                                               'little') <= 0:
            self.rcv_error = True
            return
        self.rcv_messages[int.from_bytes(new_message.message_nb, 'little') - 1] = new_message
        if new_message.check_crc() is False:
            self.rcv_error = True

    def all_msg_received(self):
        return self.count_rcv_msg == self.nb_packet

    def total_bytes_correct(self):
        if self.all_msg_received():
            return np.array(
                [len(i.payload) if i is not None else 0 for i in self.rcv_messages]).sum() == self.total_bytes
        return False

    def rebuild_img(self):
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

    vs = VideoStream()
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
        # tmp = np.array([len(list(UDPMessage.from_bytes(i).payload)) for i in msg[1:]]).sum()
        # print(tmp, np.array(vs.current_image.shape).prod())
        # print(len(msg[1:]))
        topic = VideoTopic.from_message(UDPMessage.from_bytes(msg[0]))
        # print(topic.height, topic.length, topic.pixel_size, topic.total_bytes)
        for i in msg[1:]:
            topic.add_message(UDPMessage.from_bytes(i))
        test_frame: np.array = topic.rebuild_img()
        # print(np.array_equiv(frame, test_frame))
        # print(np.dtype(test_frame[0, 0, 0]))
        # print(np.dtype(frame[0, 0, 0]))

        cv2.imshow("preview", test_frame)
        key = cv2.waitKey(20)
        if key == 27:  # exit on ESC
            break
    cv2.destroyWindow("preview")
