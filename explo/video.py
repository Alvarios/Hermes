import cv2


cv2.namedWindow("preview")
vc = cv2.VideoCapture(0)

if vc.isOpened(): # try to get the first frame
    rval, frame = vc.read()
    print(type(rval), type(frame))
else:
    rval = False

while rval:
    cv2.imshow("preview", frame)
    rval, frame = vc.read()
    key = cv2.waitKey(20)
    print(frame[0])
    if key == 27: # exit on ESC
        break
cv2.destroyWindow("preview")