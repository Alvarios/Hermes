# -*- coding: utf-8 -*-
"""Implementation of a class for non blocking camera recording with OpenCv.

This class can be run in a new process or a new thread and can be used to read images from a camera.

"""
from threading import Thread
import multiprocessing as mp
from typing import Optional, Union, NoReturn
import cv2
import datetime
import numpy as np


class Eye:
    """Implementation of a class for non blocking camera recording with OpenCv.

        Attributes :
            vc : The VideoCapture object used to read the camera.
            rval : A boolean that tell if an image has been read.
            frame : The last frame read on the camera.
            run_new_process : Specify if the Eye object must be run in a new process.
            refresh_time : Store the time spent to read the last frame in second.
            internal_pipe : Internal side of the pipe used for communication with the process.
            external_pipe : External side of the pipe used for communication with the process.
    """

    def __init__(self, src: Optional[Union[int, str]] = 0, run_new_process: Optional[bool] = False) -> None:
        """Create a new Eye instance.

        :param src: The video source used for VideoCapture.
        :param run_new_process: Specify if the Eye object must be run in a new process.
        """
        self.vc = cv2.VideoCapture(src)
        (self.rval, self.frame) = self.vc.read()
        self.is_running = False
        self.run_new_process = run_new_process
        self.refresh_time = 1
        self.internal_pipe, self.external_pipe = mp.Pipe()

    def _work(self) -> NoReturn:
        """Execute the setup and the main loop of the class."""
        self._setup()
        self._loop()

    def _setup(self) -> NoReturn:
        """Setup function of the class."""
        self.is_running = True

    def _loop(self) -> NoReturn:
        """Main loop of the class"""
        while self.is_running:
            if self.run_new_process and self.internal_pipe.poll():
                command = self.internal_pipe.recv()
                if type(command) is tuple:
                    self.internal_pipe.send(command[0](self, **command[1]))
            start_time = datetime.datetime.now()
            (self.rval, self.frame) = self.vc.read()
            self.refresh_time = (datetime.datetime.now() - start_time).total_seconds()

    def start(self) -> NoReturn:
        """Start a new thread or a new process for asynchronous camera reading.

        :return eye: The current instance of the class.
        """
        if self.run_new_process is False:
            self._start()
        else:
            mp.Process(target=self._start()).start()
        return self

    def _start(self) -> NoReturn:
        """Start the thread of the class."""
        Thread(target=self._work, args=()).start()

    def stop(self) -> NoReturn:
        """Call to _stop function."""
        if self.run_new_process is False:
            return self._stop()
        self.external_pipe.send((Eye._stop, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _stop(self) -> NoReturn:
        """Stop the thread of the instance of the class."""
        self.is_running = False

    def read(self) -> np.array:
        """Call to _read function.
        :return frame: The last frame read on the camera.
        """
        if self.run_new_process is False:
            return self._read()
        self.external_pipe.send((Eye._read, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()

    def _read(self) -> np.array:
        """Return the last frame read on the camera.

        :return frame: The last frame read on the camera.
        """
        return self.frame

    def _get_refresh_time(self) -> float:
        """Return the time spent to read the last frame.

        : return refresh_time: The time spent to read the last frame.
        """
        return self.refresh_time

    def get_refresh_time(self) -> float:
        """Call to _get_refresh_time.

        : return refresh_time: The time spent to read the last frame.
        """
        if self.run_new_process is False:
            return self._get_refresh_time()
        self.external_pipe.send((Eye._get_refresh_time, {}))
        while self.external_pipe.poll() is False:
            pass
        return self.external_pipe.recv()
