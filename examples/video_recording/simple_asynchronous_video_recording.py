# -*- coding: utf-8 -*-
"""Example of how to use CV2AsynchronousVideoCapture.

This script shows how to use CV2AsynchronousVideoCapture class to record video
 flux from the camera of the computer and display it in a separate window
 using OpenCV.

Press ESC in the preview window to quit the example while running.
"""
import datetime

import cv2

from hermes.camera.CV2AsynchronousVideoCapture import \
    CV2AsynchronousVideoCapture

if __name__ == "__main__":
    # Selection of the camera number to use for recording, 0 will work for
    # most cases
    video_source_number = 0

    # Chose to run the recorder in a new process.
    # By default, the recorder runs in a Thread forked from the main process.
    # Setting this value tu True will allow to run the recorder using another
    # CPU core, but it is in general slower due to Python limitations.
    run_new_process = False

    recorder = CV2AsynchronousVideoCapture(src=video_source_number,
                                           run_new_process=run_new_process)
    recorder.start()  # Do not forget to start the recorder after creation!!

    # Create a new window to display the video recorded
    cv2.namedWindow("preview")

    time_start = datetime.datetime.now()
    total_recorded_frames = 0
    continue_recording = True

    while continue_recording:
        # Get the last frame of the recorder and display it in the OpenCV
        # preview window
        last_frame = recorder.read_frame()

        # Need to check the last frame is not None in case the recorder is not
        # started yet (often occur when using multiprocessing).
        if last_frame is not None:
            cv2.imshow("preview", last_frame)
        total_recorded_frames += 1

        # Wait ESC key to be pressed
        key = cv2.waitKey(20)
        if key == 27:  # exit on ESC
            continue_recording = False

    # Compute average framerate of the recorder
    time_stop = datetime.datetime.now()
    total_run_duration = (time_stop - time_start).total_seconds()
    print(f"Average FPS: {total_recorded_frames / total_run_duration}")

    # Destroy the preview window
    cv2.destroyWindow("preview")

    # Stop the recorder
    recorder.stop()
