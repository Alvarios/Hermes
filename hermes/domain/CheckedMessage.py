from __future__ import annotations
# TODO: Remove future import in the future (python version > 3.10?)
from abc import ABC, abstractmethod
from typing import Optional

from hermes.domain.Message import Message


class CheckedMessage(Message):

    @abstractmethod
    def to_bytes(self) -> bytes:
        """The result of the conversion of CheckedMessage into bytes.

        :return: The CheckedMessage converted into bytes.
        """
        raise NotImplemented

    @abstractmethod
    def validate_integrity(self) -> bool:
        """Return True if message is valid else False.

        :return: The result of integrity check.
        """
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def from_bytes(raw_message: bytes, keep_if_corrupted: Optional[
        bool] = False) -> CheckedMessage:
        """Create a new CheckedMessage from bytes.

        This function create a new message from a given byte array.
        If the message is corrupted the function will return None.

        :param raw_message: The bytes to convert into a CheckedMessage.
        :param keep_if_corrupted: Return the message even if it is corrupted
        when set to True.

        :return: A CheckedMessage if it is not corrupted else None.
        """
        raise NotImplemented
