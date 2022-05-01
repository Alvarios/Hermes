# -*- coding: utf-8 -*-
"""Implementation of a class used to manage images in VideoStream.py.

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
import math
import time
from itertools import chain
from threading import Thread
from typing import Optional, Union, NoReturn

import cv2
import numpy as np

from hermes.domain import MessageCodes as codes
from hermes.messages.UDPMessage import UDPMessage


class ImageManager:
    """A class to manage image to send.

        Constants :
            NB_PACKET_SIZE : The number of bytes to store the number of packet.
            TOTAL_BYTES_SIZE : The number of bytes to store the total size of
            incoming image (in bytes).
            HEIGHT_SIZE : The number of bytes to store height of the image.
            LENGTH_SIZE : The number of bytes to store length of the image.
            SIZE_PIXEL_SIZE : The number of bytes to store the size of a pixel
            (in bytes).
            ENCODING_SIZE : The number of bytes to encoding.
            VIDEO_PACKET_ID : The message id used for udp packet.
            NB_MSG_HEADER : The message number of the header in the topic.
            ENCODING_DICT : A dictionary containing available encoding method
            and their corresponding code.

        Attributes :
            current_image : The current image to send.
            _new_image : Specify if a new message has been received (used for
            async message processing).
            _topic : A topic used for async message processing.
            max_packet_size : The max size of a packet (in byte).
            async_msg_generation : Specify if the messages representing the
            image must be generated asynchronously.
            messages : The asynchronously generated messages.
            _is_running : Specify if the associated Thread is running (used
            for async message processing).
            encoding : Define the encoding used to send images.
            encoding_param: Parameters used to encode image. See cv2.imencode
            for more details.
                Example for jpg encoding : encoding_param =
                {"params": [int(cv2.IMWRITE_JPEG_QUALITY), 50]} where 50
                is the quality of the resulting image.

    """
    NB_PACKET_SIZE = 4
    TOTAL_BYTES_SIZE = 4
    HEIGHT_SIZE = 4
    LENGTH_SIZE = 4
    SIZE_PIXEL_SIZE = 1
    ENCODING_SIZE = 1
    NB_MSG_HEADER = 0
    ENCODING_DICT = {1: ".jpg"}

    def __init__(self, max_packet_size: Optional[int] = 5000,
                 async_msg_generation: Optional[bool] = False,
                 encoding: Optional[int] = 0,
                 encoding_param: Optional[Union[dict, None]] = None) -> None:
        """Create a new ImageManager with given parameters.

        :param max_packet_size: The max size of a packet (in byte).
        :param async_msg_generation: Specify if the messages representing the
        image must be generated asynchronously.
        :param encoding: Define the encoding used to send images.
        :param encoding_param: Parameters used to encode image. See
        cv2.imencode for more details.
        """
        self.current_image: np.array = np.array([])
        self._new_image = False
        self._topic = 0
        self.max_packet_size: int = max_packet_size
        self.async_msg_generation = async_msg_generation
        self.messages: iter = iter([])
        self.is_running = False
        self.encoding = encoding
        self.encoding_param = \
            encoding_param if encoding_param is not None else {}

    def start(self) -> ImageManager:
        """Start a new thread if async_msg_generation is True.

        :return image_manager: The current instance of the class.
        """
        if self.async_msg_generation:
            Thread(target=self._work, args=()).start()
        return self

    def _work(self) -> NoReturn:
        """Execute the setup and the main loop of the class."""
        self._setup()
        self._loop()

    def _setup(self) -> None:
        """Setup function of the class."""
        self.is_running = True
        self.messages = iter([])

    def _loop(self) -> NoReturn:
        """Main loop of the class"""
        while self.is_running and self.async_msg_generation:
            if self._new_image is True:
                self.messages = self.get_messages(self._topic, force=True)
                self._topic += 1
                self._new_image = False
            else:
                time.sleep(.001)

    def stop(self) -> None:
        """Stop the thread of the instance of the class."""
        self.is_running = False

    def refresh_image(self, new_image: np.array) -> None:
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
        """Split current_image into bytes with a maximal length of
        max_packet_size.

        :return: An iterator containing bytes representing the current_image.
        """
        if self.encoding == 0:
            return map(lambda x: x.tobytes(),
                       np.array_split(self.current_image.flatten(),
                                      math.ceil(np.array(
                                          self.current_image.shape).prod() / self.max_packet_size)))
        if self.encoding in ImageManager.ENCODING_DICT.keys():
            result, img = cv2.imencode(
                ImageManager.ENCODING_DICT[self.encoding], self.current_image,
                **self.encoding_param)
            return map(lambda x: x.tobytes(),
                       np.array_split(img.flatten(), math.ceil(np.array(
                           self.current_image.shape).prod() / self.max_packet_size)))

    @staticmethod
    def get_header_msg(topic: int, nb_packet: int, total_bytes: int,
                       height: int, length: int,
                       pixel_size: int, encoding: Optional[int] = 0) -> bytes:
        """Return a UDPMessage with image metadata.

        :param topic: The topic associated to the image.
        :param nb_packet: The total number of data packet that will be send.
        :param total_bytes: The total number of bytes of the image.
        :param height: The height of the image.
        :param length: The length of the image.
        :param pixel_size: The size of a pixel.
        :param encoding: The encoding of the pixel (default 0 = None).
        :return: The UDPMessage containing image metadata.
        """
        return UDPMessage(code=codes.VIDEO_STREAM, topic=topic,
                          subtopic=ImageManager.NB_MSG_HEADER,
                          payload=nb_packet.to_bytes(
                              ImageManager.NB_PACKET_SIZE,
                              'little') + total_bytes.to_bytes(
                              ImageManager.TOTAL_BYTES_SIZE,
                              'little') + height.to_bytes(
                              ImageManager.HEIGHT_SIZE,
                              'little') + length.to_bytes(
                              ImageManager.LENGTH_SIZE,
                              'little') + pixel_size.to_bytes(
                              ImageManager.SIZE_PIXEL_SIZE,
                              'little') + encoding.to_bytes(
                              ImageManager.ENCODING_SIZE, 'little')).to_bytes()

    def get_pixel_size(self) -> int:
        """Return the size of a pixel (3 for RGB else 1 for gray scale).

        :return: The size of a pixel.
        """
        return 3 if len(self.current_image.shape) == 3 else 1

    def get_messages(self, topic: int, force: Optional[bool] = False) -> iter:
        """Return a list of bytes representing the messages to send.

        :param topic: The topic associated to the image.
        :param force: Specify if tje messages must be re-computed.
        :return: An iterator containing the the messages to send as bytes.
        """
        if self.async_msg_generation and (force is False):
            return self.messages
        img_split = self.split_image()
        to_msg = lambda enum: UDPMessage(code=codes.VIDEO_STREAM,
                                         payload=enum[1], topic=topic,
                                         subtopic=enum[0] + 1).to_bytes()
        img_messages = map(to_msg, enumerate(img_split))
        header = ImageManager.get_header_msg(topic, math.ceil(np.array(
            self.current_image.shape).prod() / self.max_packet_size),
                                             int(np.array(
                                                 self.current_image.shape)
                                                 .prod()),
                                             self.current_image.shape[0],
                                             self.current_image.shape[1],
                                             self.get_pixel_size(),
                                             encoding=self.encoding)
        return chain([header], img_messages)
