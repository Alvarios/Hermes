from __future__ import annotations
# TODO: Remove future import in the future (python version > 3.10?)
from abc import ABC, abstractmethod
import numpy as np


class AsynchronousVideoCapture(ABC):

    @abstractmethod
    def start(self) -> AsynchronousVideoCapture:
        """Start an AsynchronousVideoCapture and returns the current instance.

        :return: The current instance of the class.
        """
        raise NotImplemented

    @abstractmethod
    def stop(self) -> None:
        """Stop the AsynchronousVideoCapture process"""
        raise NotImplemented

    @abstractmethod
    def read_frame(self) -> np.array:
        """Return the last _frame read on the camera.

        :return: The last _frame captured by the video source.
        """
        raise NotImplemented

    @abstractmethod
    def get_frame_rate(self) -> float:
        """Return the current _frame rate of the video capture.

        :return: The current _frame rate of the video capture.
        """
        raise NotImplemented
