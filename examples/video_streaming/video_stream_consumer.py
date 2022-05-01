# -*- coding: utf-8 -*-
"""Example of video streaming consumer.

This script receive the video stream of a VideoStream emitter and will display it in a new window.
The emitter of this script can be the script video_stream_emitter.py

Press ESC to quit the example while running.
"""

from hermes.stream.VideoStream import VideoStream
import cv2
import datetime

if __name__ == "__main__":
    consumer_ip = input("Ip address of consumer : \n")
    consumer_port = input("Port of consumer : \n")
    consumer_address_port = (consumer_ip, int(consumer_port))
    consumer = VideoStream(role=VideoStream.CONSUMER, socket_ip=consumer_address_port[0],
                           socket_port=consumer_address_port[1], use_rcv_img_buffer=False, max_queue_size=10000).start()

    while consumer.get_is_running() is False:
        pass

    cv2.namedWindow("preview")

    rcv_frame = consumer.get_rcv_img()
    while rcv_frame is None:
        rcv_frame = consumer.get_rcv_img()
    last_frame = rcv_frame

    start = datetime.datetime.now()
    cpt = 0
    while True:
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
    consumer.time_stop()
