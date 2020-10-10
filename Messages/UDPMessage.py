# -*- coding: utf-8 -*-
"""Implementation of a general message that can be used for UDP communication.

This module provides a class that represent a general message that can be used for UDP communication.
"""

from typing import Union, Optional
import time
import zlib


class UDPMessage:
    """A class that represent a general message that can be used for UDP communication.

    The message is designed to be convert as bytes with method to_bytes to be send on the network.
    When the message is received it can be regenerated with the method from_bytes.

    The format of the message in bytes is the following :
        msg_id - time_creation - topic - message_nb - payload - crc

    Please see the constants values to know how long are each block of the message.

    The messages use crc32 to detect errors during transmission. It is useful for protocol like UDP
    that do not check if errors occur during transmission. This class also stores message creation
    time to be able to know message order that is not possible with UDP. Finally this class
    implement a system of topics and message number to allow sending content in multiple parts.

        Constants :
            MSG_ID_LENGTH : The number of bytes to store the message id.
            TIME_CREATION_LENGTH : The number of bytes to store the time creation.
            TOPIC_LENGTH : The number of bytes to store topic.
            MSG_NUMBER_LENGTH : The number of bytes to store message_nb.
            CRC_LENGTH : The number of bytes to store crc.
            PADDING_VALUE : The value to use for padding.
            MSG_MAX_SIZE : The max size of user data of an UDP datagram.

        Attributes :
            payload : The payload of the message.
            msg_id : The id of the message. It tells what to do with incoming message.
            time_creation : The time of creation of the message in microseconds.
            topic : The topic of the message. Needed for multipart content.
            message_nb : The message number of the message in this topic.
            crc : The CRC32 of the message.

    """
    MSG_ID_LENGTH = 4
    TIME_CREATION_LENGTH = 8
    TOPIC_LENGTH = 4
    MSG_NUMBER_LENGTH = 4
    CRC_LENGTH = 4
    PADDING_VALUE = 0
    MSG_MAX_SIZE = 65535
    PAYLOAD_MAX_SIZE = MSG_MAX_SIZE - MSG_ID_LENGTH - TIME_CREATION_LENGTH - TOPIC_LENGTH - \
                       MSG_NUMBER_LENGTH - CRC_LENGTH

    def __init__(self, msg_id: Optional[Union[bytes, int]] = bytes(), payload: Optional[Union[bytes, str]] = bytes(),
                 topic: Optional[Union[bytes, int]] = bytes(),
                 message_nb: Optional[Union[bytes, int]] = bytes()) -> None:
        """Create a new message with given parameters.

        :param msg_id: The id of the message. It tells what to do with incoming message.
        :param payload: The payload of the message.
        :param topic: The topic of the message.
        :param message_nb: The message number of the message in this topic.
        """
        if len(payload) > UDPMessage.PAYLOAD_MAX_SIZE:
            raise ValueError
        if type(msg_id) == int:
            msg_id = msg_id.to_bytes(UDPMessage.MSG_ID_LENGTH, 'little')
        if type(payload) == str:
            payload = payload.encode('utf8')
        if type(topic) == int:
            topic = topic.to_bytes(UDPMessage.TOPIC_LENGTH, 'little')
        if type(message_nb) == int:
            message_nb = message_nb.to_bytes(UDPMessage.MSG_NUMBER_LENGTH, 'little')

        if len(msg_id) > UDPMessage.MSG_ID_LENGTH:
            raise ValueError
        if len(topic) > UDPMessage.TOPIC_LENGTH:
            raise ValueError
        if len(message_nb) > UDPMessage.MSG_NUMBER_LENGTH:
            raise ValueError

        self.payload: bytes = payload
        self.msg_id: bytes = msg_id + bytes([UDPMessage.PADDING_VALUE] * (UDPMessage.MSG_ID_LENGTH - len(msg_id)))
        self.time_creation: bytes = int(time.time() * 1_000_000).to_bytes(UDPMessage.TIME_CREATION_LENGTH, 'little')
        self.topic: bytes = topic + bytes([UDPMessage.PADDING_VALUE] * (UDPMessage.TOPIC_LENGTH - len(topic)))
        self.message_nb: bytes = message_nb + bytes(
            [UDPMessage.PADDING_VALUE] * (UDPMessage.MSG_NUMBER_LENGTH - len(message_nb)))
        self.full_content = self.msg_id + self.time_creation + self.topic + self.message_nb + self.payload
        self.crc = zlib.crc32(self.full_content).to_bytes(UDPMessage.CRC_LENGTH, 'little')

    def check_crc(self) -> bool:
        """Return True if crc is correct else False

        :return crc_correct: The result of crc check.
        """
        return self.crc == zlib.crc32(self.full_content).to_bytes(UDPMessage.CRC_LENGTH, 'little')

    def to_bytes(self) -> bytes:
        """The result of the conversion of the message into bytes.

        The format of the message in bytes is the following :
            msg_id - time_creation - topic - message_nb - payload - crc

        :return msg_bytes: The message converted into bytes.
        """
        return self.full_content + self.crc

    @staticmethod
    def from_bytes(msg_bytes: bytes):
        """Create a new message from bytes.

        This function create a new message from a given byte array. If the message is corrupted
        the function will return None.

        :param msg_bytes: The bytes to convert into a UDPMessage.

        :return msg: The message if it is not corrupted else None.
        """
        msg_id = msg_bytes[: UDPMessage.MSG_ID_LENGTH]
        time_creation = msg_bytes[UDPMessage.MSG_ID_LENGTH: UDPMessage.MSG_ID_LENGTH + UDPMessage.TIME_CREATION_LENGTH]
        topic = msg_bytes[
                UDPMessage.MSG_ID_LENGTH + UDPMessage.TIME_CREATION_LENGTH:
                UDPMessage.MSG_ID_LENGTH + UDPMessage.TIME_CREATION_LENGTH + UDPMessage.TOPIC_LENGTH]
        message_nb = msg_bytes[
                     UDPMessage.MSG_ID_LENGTH + UDPMessage.TIME_CREATION_LENGTH + UDPMessage.TOPIC_LENGTH:
                     UDPMessage.MSG_ID_LENGTH + UDPMessage.TIME_CREATION_LENGTH + UDPMessage.TOPIC_LENGTH +
                     UDPMessage.MSG_NUMBER_LENGTH]
        payload = msg_bytes[UDPMessage.MSG_ID_LENGTH + UDPMessage.TIME_CREATION_LENGTH +
                            UDPMessage.TOPIC_LENGTH + UDPMessage.MSG_NUMBER_LENGTH: -UDPMessage.CRC_LENGTH]
        crc = msg_bytes[-UDPMessage.CRC_LENGTH:]
        msg = UDPMessage(msg_id=msg_id, payload=payload, message_nb=message_nb, topic=topic)
        msg.time_creation = time_creation
        msg.crc = crc
        msg.full_content = msg.msg_id + msg.time_creation + msg.topic + msg.message_nb + msg.payload
        if msg.check_crc():
            return msg


if __name__ == "__main__":
    print(zlib.crc32(bytes("hello world", "utf8")))
    print(zlib.crc32(bytes("hello world", "utf8")).to_bytes(UDPMessage.CRC_LENGTH, 'little'))
    print(bytes([0, 1]) + bytes([2] * 2))
