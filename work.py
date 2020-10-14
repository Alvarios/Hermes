import time
from Polypheme.Eye import Eye
from Stream.VideoStream import ImageManager

n_iter = 10000
eye = Eye(run_new_process=False).start()
im = ImageManager(60000)
time.sleep(2)

print("Start")
start = time.time()
for i in range(n_iter):
    im.refresh_image(eye.read())
    im.get_messages(i)

# print(im.split_image())
print(type(im.split_image()))
# print(len(im.split_image()))
dt = (time.time() - start)
eye.stop()
print(1 / (dt / n_iter))
print(dt)

# 354.9623928777193
# 28.171998500823975