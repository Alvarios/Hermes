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
    im.get_messages_express(eye.read(), i)
    # im.refresh_image(eye.read())
    # im.get_messages(i)

dt = (time.time() - start)
eye.stop()
print(1 / (dt / n_iter))
print(dt)

# 496.1280879282382
# 22.720658540725708


# 477.94057865247504
# 20.923103094100952
