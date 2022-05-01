# -*- coding: utf-8 -*-
"""Implementation of a class used to rebuild images in VideoStream.py.

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
from typing import Optional, List, Union, NoReturn

import cv2
import numpy as np

from hermes.messages.UDPMessage import UDPMessage
from hermes.stream.ImageManager import ImageManager


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

    def __init__(self, nb_packet: int, total_bytes: int, height: int,
                 length: int, pixel_size: int, time_creation: int,
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
        self.rcv_messages: List[Union[UDPMessage, None]] = [None for i in
                                                            range(nb_packet)]
        self.rcv_error = False
        self.count_rcv_msg = 0
        self.encoding = encoding

    @property
    def nb_packet(self) -> int:
        return self._nb_packet

    @nb_packet.setter
    def nb_packet(self, value: int) -> None:
        if value < 1 or value >= pow(2, 8 * ImageManager.NB_PACKET_SIZE):
            raise ValueError
        self._nb_packet = value

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    @total_bytes.setter
    def total_bytes(self, value: int) -> None:
        if value < 1 or value >= pow(2, 8 * ImageManager.TOTAL_BYTES_SIZE):
            raise ValueError
        self._total_bytes = value

    @property
    def pixel_size(self) -> int:
        return self._pixel_size

    @pixel_size.setter
    def pixel_size(self, value: int) -> None:
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

        The position of the message in rcv_message list will depend on subtopic (start at 1).

        :param new_message: The message to add to the topic.
        """
        if type(new_message) is not UDPMessage:
            return
        self.count_rcv_msg += 1
        if int.from_bytes(new_message.subtopic,
                          'little') > self.nb_packet or int.from_bytes(
                new_message.subtopic,
                'little') <= 0:
            self.rcv_error = True
            return
        self.rcv_messages[
            int.from_bytes(new_message.subtopic, 'little') - 1] = new_message
        if new_message.validate_integrity() is False:
            self.rcv_error = True

    def all_msg_received(self) -> bool:
        """Return True if all messages of the topic have been received else False.

        :return: A bool that tell if all messages have been received.
        """
        return self.count_rcv_msg == self.nb_packet

    def total_bytes_correct(self) -> bool:
        """Check if the expected number of bytes is equal to the received number of bytes.

        :return: A bool that tell if a correct number of bytes have been received.
        """
        if self.all_msg_received():
            return np.array(
                [len(i.payload) if i is not None else 0 for i in
                 self.rcv_messages]).sum() == self.total_bytes
        return False

    def rebuild_img(self) -> np.array:
        """Return an image as numpy array if all required messages have been received and nor error is detected.

        :return: The image encoded in the received messages. None if an error is detected.
        """
        if self.encoding != 0:
            try:
                encoded_img = np.concatenate(
                    [np.frombuffer(i.payload, np.uint8) for i in
                     self.rcv_messages])
                encoded_img = encoded_img.reshape(len(encoded_img), 1)
                return cv2.imdecode(encoded_img, 1)
            except:
                return None

        if self.total_bytes % self.pixel_size != 0 or self.total_bytes % self.height != 0 \
                or self.total_bytes % self.length != 0:
            return None
        if self.pixel_size != 1:
            try:
                return np.concatenate(
                    [np.frombuffer(i.payload, np.uint8) for i in
                     self.rcv_messages]).reshape(
                    (self.height, self.length, self.pixel_size)).astype(
                    np.uint8)
            except:
                return None
        return np.concatenate([np.frombuffer(i.payload, np.uint8) for i in
                               self.rcv_messages]).reshape(
            (self.height, self.length)).astype(np.uint8)

    @staticmethod
    def from_message(new_msg: UDPMessage) -> VideoTopic:
        """Create a new VideoTopic from a UDPMessage.

        :param new_msg: The message used to create VideoTopic.
        :return: A new VideoTopic created from input message.
        """
        payload = new_msg.payload
        cursor_pos = 0
        nb_packet = int.from_bytes(
            payload[cursor_pos:cursor_pos + ImageManager.NB_PACKET_SIZE],
            'little')
        cursor_pos += ImageManager.NB_PACKET_SIZE
        total_bytes = int.from_bytes(
            payload[cursor_pos:cursor_pos + ImageManager.TOTAL_BYTES_SIZE],
            'little')
        cursor_pos += ImageManager.TOTAL_BYTES_SIZE
        height = int.from_bytes(
            payload[cursor_pos:cursor_pos + ImageManager.HEIGHT_SIZE],
            'little')
        cursor_pos += ImageManager.HEIGHT_SIZE
        length = int.from_bytes(
            payload[cursor_pos:cursor_pos + ImageManager.LENGTH_SIZE],
            'little')
        cursor_pos += ImageManager.LENGTH_SIZE
        pixel_size = int.from_bytes(
            payload[cursor_pos:cursor_pos + ImageManager.SIZE_PIXEL_SIZE],
            'little')
        cursor_pos += ImageManager.SIZE_PIXEL_SIZE
        encoding = int.from_bytes(
            payload[cursor_pos:cursor_pos + ImageManager.ENCODING_SIZE],
            'little')
        time_creation = int.from_bytes(new_msg.time_creation, 'little')
        return VideoTopic(nb_packet, total_bytes, height, length, pixel_size,
                          time_creation, encoding=encoding)
