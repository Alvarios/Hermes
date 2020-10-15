import time
import numpy as np
from Stream.VideoStream import ImageManager
from Polypheme.Eye import Eye

n_iter = 100
work = np.array(480 * [640 * [3*[255]]])
eye = Eye().start()
im = ImageManager(30000, async_msg_generation=True).start()
time.sleep(2)
im.refresh_image(eye.read())
time.sleep(1)

print("start")
start = time.time()
for i in range(n_iter):
    im.refresh_image(eye.read())
    msgs = im.get_messages(i)
    for msg in msgs:
        print(len(msg))
dt = time.time() - start
eye.stop()
im.stop()
print(1/(n_iter / dt))
print(n_iter / dt)