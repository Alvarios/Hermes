# -*- coding: utf-8 -*-
"""Example of video streaming emitter for raspberry.

This script get the flux from the camera and send it to given ip and port.
The consumer of this script can be the script video_stream_consumer.py
"""

from hermes.stream.VideoStream import VideoStream
import cv2
from hermes.polypheme.CV2AsynchronousVideoCapture import CV2AsynchronousVideoCapture

if __name__ == "__main__":
    emitter_ip = input("Ip address of emitter : \n")
    emitter_port = input("Port of emitter : \n")
    consumer_ip = input("Ip address of consumer : \n")
    consumer_port = input("Port of consumer : \n")
    encoding_param = {"params": [int(cv2.IMWRITE_JPEG_QUALITY), 50]}
    emitter_address_port = (emitter_ip, int(emitter_port))
    consumer_address_port = (consumer_ip, int(consumer_port))
    emitter = VideoStream(role=VideoStream.EMITTER, socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1], run_new_process=False, encoding=1,
                          encoding_param=encoding_param).start()
    eye = CV2AsynchronousVideoCapture(src=0, run_new_process=False).start()
    while emitter.get_is_running() is False:
        pass
    while eye.read_frame() is None:
        pass
    emitter.add_subscriber(consumer_address_port)
    while True:
        emitter.refresh_image(eye.read_frame())
