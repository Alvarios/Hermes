# -*- coding: utf-8 -*-
"""Example of video streaming emitter for raspberry.

This script get the flux from the camera and send it to given ip and port.
The consumer of this script can be the script video_stream_consumer.py
"""

from Stream.VideoStream import VideoStream
import numpy as np
from Polypheme.Eye import Eye
import time

if __name__ == "__main__":
    emitter_ip = input("Ip address of emitter : \n")
    emitter_port = input("Port of emitter : \n")
    consumer_ip = input("Ip address of consumer : \n")
    consumer_port = input("Port of consumer : \n")
    emitter_address_port = (emitter_ip, int(emitter_port))
    consumer_address_port = (consumer_ip, int(consumer_port))
    emitter = VideoStream(role=VideoStream.EMITTER, socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1], run_new_process=False)
    eye = Eye(src=0, run_new_process=False).start()
    while emitter.get_is_running() is False:
        pass
    emitter.add_subscriber(consumer_address_port)
    while True:
        emitter.refresh_image(eye.read())

    emitter.stop()

    # with picamera.PiCamera() as camera:
    #     camera.resolution = (320, 240)
    #     camera.framerate = 24
    #     time.sleep(2)
    #     output = np.empty((240, 320, 3), dtype=np.uint8)
    #     camera.capture(output, 'rgb')
    #
    #     while emitter.get_is_running() is False:
    #         pass
    #     emitter.add_subscriber(consumer_address_port)
    #     red = np.array(240*[320*[[255,0,0]]])
    #     green = np.array(240*[320*[[0,255,0]]])
    #     blue = np.array(240*[320*[[0,0,255]]])
    #     while True:
    #         camera.capture(output, 'rgb')
    #         #output = np.array(240*[320*[[255,0,0]]])
    #         emitter.refresh_image(red)
    #         #output = np.array(240*[320*[[0,255,0]]])
    #         emitter.refresh_image(green)
    #         #output = np.array(240*[320*[[0,0,255]]])
    #         emitter.refresh_image(blue)
    #     emitter.stop()
