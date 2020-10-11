import multiprocessing as mp
import time


class MyProcess(mp.Process):

    def __init__(self):
        super().__init__(target=self.process)
        self.internal_pipe, self.external_pipe = mp.Pipe()
        self.is_running = False

    def get_pipe(self):
        return self.external_pipe

    def process(self):
        self.setup()
        self.loop()

    @staticmethod
    def test_print(msg, nb_print):
        for i in range(nb_print):
            print(msg)

    def test(self, msg, nb_print):
        self.external_pipe.send((self.test_print, {"msg": msg, "nb_print": nb_print}))

    @staticmethod
    def test_print2():
        print("OK")

    def test2(self):
        self.external_pipe.send((self.test_print2, {}))

    def loop(self):
        while self.is_running:
            msg = self.internal_pipe.recv()
            if msg == "STOP!":
                self.is_running = False
            if msg == "wtf":
                self.internal_pipe.send(self.is_running)
            if type(msg) is str:
                print(msg)
            if type(msg) is tuple:
                msg[0](**msg[1])

    def setup(self):
        print(type(self.internal_pipe))
        self.is_running = True

    def stop(self):
        self.external_pipe.send("STOP!")
        self.is_running = False

    def get_is_running(self):
        self.external_pipe.send("wtf")
        reply = self.external_pipe.recv()
        while reply is None:
            reply = self.external_pipe.recv()
        return reply


if __name__ == "__main__":
    tst = MyProcess()
    pipe = tst.get_pipe()
    tst.start()
    time.sleep(1)
    for i in range(10):
        pipe.send("hello")
        print(tst.get_is_running())
        time.sleep(.1)
    tst.test("TEST", 5)
    tst.test2()
    tst.stop()
    print("end")
    time.sleep(.5)
    a1, a2 = mp.Pipe()
    a2.send(None)
    print(a1.poll())
    print(a1.recv())
