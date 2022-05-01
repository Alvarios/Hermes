# -*- coding: utf-8 -*-
"""Abstract Base Class for a simple non-blocking network channel based on IP.


    Copyright (C) 2022  Clement Dulouard

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
from abc import ABC, abstractmethod
from typing import Optional, Union, Tuple


class AsynchronousIPChannel(ABC):
    @abstractmethod
    def start(self) -> AsynchronousIPChannel:
        """Start an AsynchronousIPChannel and returns the current instance.

        :return: The current instance of the class.
        """
        raise NotImplemented

    @abstractmethod
    def stop(self) -> None:
        """Stop the AsynchronousIPChannel process"""
        raise NotImplemented

    @abstractmethod
    def sendto(self, msg: bytes, address_port: Tuple[str, int]) -> None:
        """Stop the AsynchronousIPChannel process"""
        raise NotImplemented

    @abstractmethod
    def message_available(self) -> bool:
        """Return True if messages are available in the queue.

        :return: A bool that tell if messages are available and can be
        retrieves with pull.
        """
        raise NotImplemented

    @abstractmethod
    def pull(self) -> Tuple[bytes, Tuple[str, int]]:
        """Return the first message waiting message.

        :return: The first waiting the queue.
        """
        raise NotImplemented
