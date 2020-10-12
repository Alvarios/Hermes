# -*- coding: utf-8 -*-
"""Example of video streaming on the same machine.

This script get the flux from the camera of the computer and send it to itself using
VideoStream object as emitter and consumer.

Press ESC to quit the example while running.
"""

from Stream.VideoStream import VideoStream, VideoTopic, ImageManager, TopicManager
import cv2
from Messages.UDPMessage import UDPMessage
import datetime

if __name__ == "__main__":

    cv2.namedWindow("preview")
    vc = cv2.VideoCapture(0)
    im = ImageManager(max_packet_size=60000)

    if vc.isOpened():
        rval, frame = vc.read()
    else:
        rval = False

    start = datetime.datetime.now()
    cpt = 0
    while rval:
        cpt += 1
        rval, frame = vc.read()
        im.refresh_image(frame)
        messages = im.get_messages(10)
        vt = VideoTopic.from_message(UDPMessage.from_bytes(messages[0]))
        for i in messages[1:]:
            vt.add_message(UDPMessage.from_bytes(i))
        new_frame = vt.rebuild_img()

        rval, frame = vc.read()

        cv2.imshow("preview", new_frame)

        key = cv2.waitKey(20)
        if key == 27:  # exit on ESC
            break
    stop = datetime.datetime.now()
    dt = stop - start
    print("Average IPS : ", cpt / dt.total_seconds())

    cv2.destroyWindow("preview")
