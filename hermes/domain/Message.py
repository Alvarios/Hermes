from __future__ import annotations
# TODO: Remove future import in the future (python version > 3.10?)
from abc import ABC, abstractmethod


class Message(ABC):

    @abstractmethod
    def to_bytes(self) -> bytes:
        """The result of the conversion of Message into bytes.

        :return: The CheckedMessage converted into bytes.
        """
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def from_bytes(raw_message: bytes) -> Message:
        """Create a new CheckedMessage from bytes.

        This function create a new message from a given byte array.

        :param raw_message: The bytes to convert into a CheckedMessage.

        :return: A CheckedMessage if it is not corrupted else None.
        """
        raise NotImplemented
