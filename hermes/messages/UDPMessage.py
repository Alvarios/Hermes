# -*- coding: utf-8 -*-
"""Implementation of a general message that can be used for UDP communication.

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
from typing import Union, Optional
import time
import zlib

from hermes.domain.CheckedMessage import CheckedMessage


class UDPMessage(CheckedMessage):
    """A class that represent a general message that can be used for UDP
    communication.

    The message is designed to be converted as bytes with method to_bytes to be
    sent on the network.
    When the message is received it can be regenerated with the method
    from_bytes.

    The format of the message in bytes is the following :
        code - time_creation - topic - subtopic - payload - crc

    Please see the constants values to know how long are each block of the
    message.

    The messages use crc32 to detect errors during transmission which is useful
    for UDP transmission.
    that do not check if errors occur during transmission. This class also
    stores message creation
    time to be able to know message order that is not possible with UDP.
    Finally, this class implements a system of topics and message number to
    allow sending content in multiple parts.

        Constants :
            MSG_ID_LENGTH : The number of bytes to store the message id.
            TIME_CREATION_LENGTH : The number of bytes to store the time
            creation.
            TOPIC_LENGTH : The number of bytes to store topic.
            SUBTOPIC_LENGTH : The number of bytes to store subtopic.
            CRC_LENGTH : The number of bytes to store crc.
            PADDING_VALUE : The value to use for padding.
            MSG_MAX_SIZE : The max size of user data in UDP datagrams.
            MSG_ID_END_POS: The end position of the message ID block when the
            message is represented as byte array.
            TIME_CREATION_START_POS: The start position of time creation block
            when the message is represented as byte array.
            TIME_CREATION_END_POS: The end position of time creation block
            when the message is represented as byte array.
            TOPIC_START_POS: The start position of topic block when the message
             is represented as byte array.
            TOPIC_END_POS: The end position of topic block when the message
             is represented as byte array.
            SUBTOPIC_START_POS: The start position of subtopic block when
            the message is represented as byte array.
            SUBTOPIC_END_POS: The end position of subtopic block when
            the message is represented as byte array.
            PAYLOAD_START_POS: The start position of payload block when
            the message is represented as byte array.
            PAYLOAD_END_POS: The end position of payload block when the message
             is represented as byte array.
            CRC_START_POS: The start position of crc block when the message is
            represented as byte array.

        Attributes :
            payload : The payload of the message.
            code : The id of the message. It tells what to do with incoming
            message.
            time_creation : The time of creation of the message in
            microseconds.
            topic : The topic of the message. Needed for multipart content.
            subtopic : The message number of the message in this topic.
            crc : The CRC32 of the message.

    """

    # Message section size definition
    MSG_MAX_SIZE = 65535  # Defined by UDP protocol
    MSG_ID_LENGTH = 4
    TIME_CREATION_LENGTH = 8
    TOPIC_LENGTH = 4
    SUBTOPIC_LENGTH = 4
    CRC_LENGTH = 4
    PADDING_VALUE = 0
    PAYLOAD_MAX_SIZE = MSG_MAX_SIZE - MSG_ID_LENGTH - TIME_CREATION_LENGTH - \
                       TOPIC_LENGTH - SUBTOPIC_LENGTH - CRC_LENGTH

    # Message section start and stop position definition
    MSG_ID_END_POS = MSG_ID_LENGTH

    TIME_CREATION_START_POS = MSG_ID_END_POS
    TIME_CREATION_END_POS = TIME_CREATION_START_POS + TIME_CREATION_LENGTH

    TOPIC_START_POS = TIME_CREATION_END_POS
    TOPIC_END_POS = TOPIC_START_POS + TOPIC_LENGTH

    SUBTOPIC_START_POS = TOPIC_END_POS
    SUBTOPIC_END_POS = SUBTOPIC_START_POS + SUBTOPIC_LENGTH

    PAYLOAD_START_POS = SUBTOPIC_END_POS

    # Payload size will vary so PAYLOAD_END_POS must be defined from the end
    # of the message
    PAYLOAD_END_POS = - CRC_LENGTH

    CRC_START_POS = PAYLOAD_END_POS

    def __init__(self, code: Optional[Union[bytes, int]] = bytes(),
                 payload: Optional[Union[bytes, str]] = bytes(),
                 topic: Optional[Union[bytes, int]] = bytes(),
                 subtopic: Optional[Union[bytes, int]] = bytes()) -> None:
        """Create a new message with given parameters.

        :param code: The code of the message. It tells what to do with
        incoming message (can be used like a port).
        :param payload: The payload of the message.
        :param topic: The topic associated to the message.
        Can be used to give more information about the message.
        :param subtopic: The subtopic associated to the message.
        Can be used to give extra information about the message if topic
        is already used.
        """
        if len(payload) > UDPMessage.PAYLOAD_MAX_SIZE:
            raise ValueError
        if type(code) == int:
            code = code.to_bytes(UDPMessage.MSG_ID_LENGTH, 'little')
        if type(payload) == str:
            payload = payload.encode('utf8')
        if type(topic) == int:
            topic = topic.to_bytes(UDPMessage.TOPIC_LENGTH, 'little')
        if type(subtopic) == int:
            subtopic = subtopic.to_bytes(UDPMessage.SUBTOPIC_LENGTH,
                                         'little')

        if len(code) > UDPMessage.MSG_ID_LENGTH:
            raise ValueError
        if len(topic) > UDPMessage.TOPIC_LENGTH:
            raise ValueError
        if len(subtopic) > UDPMessage.SUBTOPIC_LENGTH:
            raise ValueError

        self.payload: bytes = payload

        self.msg_id: bytes = code + bytes([UDPMessage.PADDING_VALUE] * (
                UDPMessage.MSG_ID_LENGTH - len(code)))

        self.time_creation: bytes = int(time.time() * 1_000_000).to_bytes(
            UDPMessage.TIME_CREATION_LENGTH, 'little')

        self.topic: bytes = topic + bytes([UDPMessage.PADDING_VALUE] * (
                UDPMessage.TOPIC_LENGTH - len(topic)))

        self.subtopic: bytes = subtopic + bytes(
            [UDPMessage.PADDING_VALUE] * (
                    UDPMessage.SUBTOPIC_LENGTH - len(subtopic)))

        self.full_content = self.msg_id + self.time_creation + self.topic + \
                            self.subtopic + self.payload

        self.crc = zlib.crc32(self.full_content).to_bytes(
            UDPMessage.CRC_LENGTH, 'little')

    def validate_integrity(self) -> bool:
        """Return True if message is valid else False.

        :return: The result of integrity check.
        """
        return self.crc == zlib.crc32(self.full_content).to_bytes(
            UDPMessage.CRC_LENGTH, 'little')

    def to_bytes(self) -> bytes:
        """The result of the conversion of the message into bytes.

        The format of the message in bytes is the following :
            code - time_creation - topic - subtopic - payload - crc

        :return: The message converted into bytes.
        """
        return self.full_content + self.crc

    @staticmethod
    def from_bytes(msg_bytes: bytes,
                   keep_if_corrupted: Optional[bool] = False) -> Union[
        UDPMessage]:
        """Create a new message from bytes.

        This function create a new message from a given byte array.
        If the message is corrupted the function will return None.

        :param msg_bytes: The bytes to convert into a UDPMessage.
        :param keep_if_corrupted: Return the message even if it is corrupted
        when set to True.

        :return: The message if it is not corrupted else None.
        """
        msg_id = msg_bytes[: UDPMessage.MSG_ID_END_POS]

        time_creation = msg_bytes[UDPMessage.TIME_CREATION_START_POS:
                                  UDPMessage.TIME_CREATION_END_POS]

        topic = msg_bytes[UDPMessage.TOPIC_START_POS: UDPMessage.TOPIC_END_POS]

        subtopic = msg_bytes[UDPMessage.SUBTOPIC_START_POS:
                             UDPMessage.SUBTOPIC_END_POS]

        payload = msg_bytes[
                  UDPMessage.PAYLOAD_START_POS: -
                  UDPMessage.CRC_LENGTH]

        crc = msg_bytes[UDPMessage.CRC_START_POS:]

        msg = UDPMessage(code=msg_id, payload=payload, subtopic=subtopic,
                         topic=topic)

        msg.time_creation = time_creation
        msg.crc = crc
        msg.full_content = msg.msg_id + msg.time_creation + msg.topic + \
                           msg.subtopic + msg.payload

        if msg.validate_integrity() or keep_if_corrupted:
            return msg
        return None
