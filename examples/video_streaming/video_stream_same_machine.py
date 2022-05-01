# -*- coding: utf-8 -*-
"""Example of video streaming on the same machine.

This script get the flux from the camera of the computer and send it to itself
using VideoStream object as emitter and consumer.

Press ESC in the preview window to quit the example while running.
"""
from hermes.camera.CV2AsynchronousVideoCapture import \
    CV2AsynchronousVideoCapture
from hermes.stream.VideoStream import VideoStream
import cv2
import datetime
from hermes.security.utils import generate_key_32

if __name__ == "__main__":
    # Define the video compression parameter, only JPEG is supported at the
    # moment, feel free to copy/paste this example and change the in value
    # which the compression rate for the JPEG algorithme.
    encoding_param = {"params": [int(cv2.IMWRITE_JPEG_QUALITY), 50]}

    # Set the ip and port for emitter and receiver
    emitter_address_port = ('127.0.0.1', 50000)
    consumer_address_port = ('127.0.0.1', 50001)

    key = generate_key_32()  # Generate an encryption key to cipher the video

    # Define the video emitter instance
    emitter = VideoStream(role=VideoStream.EMITTER,
                          socket_ip=emitter_address_port[0],
                          socket_port=emitter_address_port[1],
                          async_msg_generation=True, encoding=1,
                          encoding_param=encoding_param,
                          encryption_in_transit=True, key=key).start()

    # Define the video receiver instance
    consumer = VideoStream(role=VideoStream.CONSUMER,
                           socket_ip=consumer_address_port[0],
                           socket_port=consumer_address_port[1],
                           use_rcv_img_buffer=False, max_queue_size=10000,
                           encryption_in_transit=True, key=key).start()

    # Wait both instances are started
    while emitter.get_is_running() is False:
        pass
    while consumer.get_is_running() is False:
        pass

    # Tell the emitter to send video stream to the receiver ip and port
    emitter.add_subscriber(consumer_address_port)

    # Create a CV2 window to see the resulting video
    cv2.namedWindow("preview")

    # Start a video recorder to get video to send to the receiver
    recorder = CV2AsynchronousVideoCapture(src=0)
    recorder.start()  # Do not forget to start the recorder after creation!!

    # There is currently no function to make sure the recorder is started,
    # so we wait until the read_frame function return non-null value to make
    # sure the recorder is recording
    while recorder.read_frame() is None:
        pass

    last_frame = recorder.read_frame()

    time_start = datetime.datetime.now()
    total_recorded_frames = 0
    continue_streaming = True

    while continue_streaming:
        frame = recorder.read_frame()  # Read last frame of the recorder

        emitter.refresh_image(frame)  # Send the last frame from the emitter

        rcv_frame = consumer.get_rcv_img()  # And read the last received image
        if rcv_frame is not None:
            last_frame = rcv_frame
            total_recorded_frames += 1
        cv2.imshow("preview", last_frame)

        # Check if escape key is pressed to stop the process
        key = cv2.waitKey(20)
        if key == 27:  # exit on ESC
            continue_streaming = False

    # Compute average framerate of the stream
    time_stop = datetime.datetime.now()
    total_run_duration = (time_stop - time_start).total_seconds()
    print(f"Average FPS: {total_recorded_frames / total_run_duration}")

    # Destroy the preview window
    cv2.destroyWindow("preview")

    # Stop all processes
    emitter.stop()
    consumer.stop()
    recorder.stop()
