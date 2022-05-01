# -*- coding: utf-8 -*-
"""Implementation of a class for non-blocking camera recording with OpenCv.


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
from threading import Thread
import multiprocessing as mp
from typing import Optional, Union, NoReturn
import cv2
import datetime
import numpy as np

from hermes.domain.AsynchronousVideoCapture import AsynchronousVideoCapture


class CV2AsynchronousVideoCapture(AsynchronousVideoCapture):
    """Implementation of a class for non-blocking video recording using OpenCv.

        Attributes :
            _vc: The VideoCapture object used to read the camera.
            _src: The video source number to use for recording
            _frame: The last _frame read on the camera.
            _run_new_process: Specify if the CV2AsynchronousVideoCapture
            object must be run in a new process.
            _refresh_time: Store the time spent to read the last _frame in
            second.
            _internal_pipe: Internal side of the pipe used for communication
            with the process.
            _external_pipe: External side of the pipe used for communication
            with the process.
    """

    def __init__(self, src: Optional[Union[int, str]] = 0,
                 run_new_process: Optional[bool] = False) -> None:
        """Create a new CV2AsynchronousVideoCapture instance.

        :param src: The video source used for VideoCapture.
        :param run_new_process: Specify if the CV2AsynchronousVideoCapture
        instance must be run in a new process.
        """
        self._vc = None
        self._src = src
        self._frame = None
        self._is_running = False
        self._run_new_process = run_new_process
        self._refresh_time = 1
        self._internal_pipe, self._external_pipe = mp.Pipe()

    def _work(self) -> NoReturn:
        """Execute the setup and the main loop of the class."""
        self._setup()
        self._loop()

    def _setup(self) -> None:
        """Setup function of the class."""
        self._vc = cv2.VideoCapture(self._src)
        self._is_running = True

    def _loop(self) -> NoReturn:
        """Main loop of the class"""
        while self._is_running:
            if self._run_new_process and self._internal_pipe.poll():
                command = self._internal_pipe.recv()
                if type(command) is tuple:
                    self._internal_pipe.send(command[0](self, **command[1]))
            start_time = datetime.datetime.now()
            (new_frame_available, frame) = self._vc.read()
            if new_frame_available:
                self._frame = frame
            self._refresh_time = (datetime.datetime.now() -
                                  start_time).total_seconds()

    def start(self) -> CV2AsynchronousVideoCapture:
        """Start a new thread or a new process for asynchronous camera reading.

        :return: The current instance of the class.
        """
        if self._run_new_process is False:
            self._start()
        else:
            mp.Process(target=self._start).start()
        return self

    def _start(self) -> None:
        """Start the thread of the class."""
        Thread(target=self._work, args=()).start()

    def stop(self) -> None:
        """Stop the video capture process."""
        if self._run_new_process is False:
            return self._stop()
        self._external_pipe.send((CV2AsynchronousVideoCapture._stop, {}))
        while self._external_pipe.poll() is False:
            pass
        return self._external_pipe.recv()

    def _stop(self) -> None:
        """Stop the video capture process."""
        self._is_running = False

    def read_frame(self) -> np.array:
        """Return the last frame read on the camera.

        :return: The last frame read on the camera.
        """
        if self._run_new_process is False:
            return self._read_frame()
        self._external_pipe.send((CV2AsynchronousVideoCapture._read_frame, {}))
        while self._external_pipe.poll() is False:
            pass
        return self._external_pipe.recv()

    def _read_frame(self) -> np.array:
        """Return the last frame read on the camera.

        :return: The last frame read on the camera.
        """
        return self._frame

    def _get_frame_rate(self) -> float:
        """Return the current frame rate of the video capture.

        :return: The current frame rate of the video capture.
        """
        return self._refresh_time

    def get_frame_rate(self) -> float:
        """Return the current frame rate of the video capture.

        :return: The current frame rate of the video capture.
        """
        if self._run_new_process is False:
            return self._get_frame_rate()
        self._external_pipe.send(
            (CV2AsynchronousVideoCapture._get_frame_rate, {}))
        while self._external_pipe.poll() is False:
            pass
        return self._external_pipe.recv()
