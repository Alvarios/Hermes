# -*- coding: utf-8 -*-
"""Example of video streaming on the same machine.

This script get the flux from the camera of the computer and send it to itself using
VideoStream object as emitter and consumer.

Press ESC to quit the example while running.
"""
from Stream.VideoStream import VideoStream
import cv2
import datetime

if __name__ == "__main__":
    emitter_address_port = ('127.0.0.1', 50000)
    consumer_address_port = ('127.0.0.1', 50001)
    emitter = VideoStream(role=VideoStream.EMITTER, socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1])
    consumer = VideoStream(role=VideoStream.CONSUMER, socket_ip=consumer_address_port[0],
                           socket_port=consumer_address_port[1], use_rcv_img_buffer=False, max_queue_size=10000)
    while emitter.get_is_running() is False:
        pass
    while consumer.get_is_running() is False:
        pass
    emitter.add_subscriber(consumer_address_port)

    cv2.namedWindow("preview")
    vc = cv2.VideoCapture(0)

    if vc.isOpened():
        rval, frame = vc.read()
    else:
        rval = False

    last_frame = frame

    start = datetime.datetime.now()
    cpt = 0
    while rval:
        rval, frame = vc.read()
        emitter.refresh_image(frame)
        rcv_frame = consumer.get_rcv_img()
        if rcv_frame is not None:
            last_frame = rcv_frame
            cpt += 1
        cv2.imshow("preview", last_frame)

        key = cv2.waitKey(20)
        if key == 27:  # exit on ESC
            break

    stop = datetime.datetime.now()
    dt = stop - start
    print("Average IPS : ", cpt / dt.total_seconds())
    cv2.destroyWindow("preview")
    emitter.stop()
    consumer.stop()
