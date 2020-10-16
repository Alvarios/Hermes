# -*- coding: utf-8 -*-
"""Example of video streaming emitter.

This script get the flux from the camera and send it to given ip and port.
The consumer of this script can be the script video_stream_consumer.py
"""

from hermes.streams.VideoStream import VideoStream
import cv2

if __name__ == "__main__":
    emitter_ip = input("Ip address of emitter : \n")
    emitter_port = input("Port of emitter : \n")
    consumer_ip = input("Ip address of consumer : \n")
    consumer_port = input("Port of consumer : \n")
    emitter_address_port = (emitter_ip, int(emitter_port))
    consumer_address_port = (consumer_ip, int(consumer_port))
    emitter = VideoStream(role=VideoStream.EMITTER, socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1]).start()
    while emitter.get_is_running() is False:
        pass
    emitter.add_subscriber(consumer_address_port)

    vc = cv2.VideoCapture(0)

    if vc.isOpened():
        rval, frame = vc.read()
    else:
        rval = False

    last_frame = frame

    while rval:
        rval, frame = vc.read()
        emitter.refresh_image(frame)

    emitter.stop()
