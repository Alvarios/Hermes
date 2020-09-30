import socket
from threading import Thread
from typing import Optional
from Message import *
import hashlib
import time


class Server(Thread):

    def __init__(self, ip: str, port: int, password: str) -> None:
        """
        Creat a new Listener object
        :param ip:
        The ip we want to use for the server
        :param port:
        The port we want to use for the server
        :param hash_pass:
        The hashed password of the server
        """
        Thread.__init__(self)
        self.is_running: bool = False
        self.ip: str = ip
        self.port: int = port
        self.socket: socket.socket = socket.socket(socket.AF_INET,  # Internet
                                                   socket.SOCK_DGRAM)  # UDP

        self.hash_pass = hashlib.sha1(bytes(password, "utf8")).hexdigest()
        self.client_is_connected: bool = False
        self.client_ip: str = ""
        self.client_port: int = 0

        self.send_socket = socket.socket(socket.AF_INET,  # Internet
                                         socket.SOCK_DGRAM)

    def listen(self) -> None:
        """
        Infinite loop for the server
        :return:
        None
        """
        self.socket.bind((self.ip, self.port))
        while self.is_running:
            data, addr = self.socket.recvfrom(2048)  # buffer size is 1024 bytes

            # DEBUG A ENLEVER PLUS TARD
            # data_string = data.decode("utf-8")
            #
            # message = Message.check_message(data_string)
            # if message.id == 1:
            #     self.connection(message, addr)
            # if self.client_is_connected == True:
            #     if message.id == 3:
            #         self.send(str(self.robot), 4)
            #     if message.id == 5:
            #         self.robot.set_targets(message.content)
            #         self.send('{ "answer" : 1 }', 6)

    # def check_pass(self, pass_to_verif: str) -> bool:
    #     """
    #     Verify if the password entered by client is the one of the server
    #     :param pass_to_verif:
    #     Hashed password to compare with the password of the server
    #     :return:
    #     Bool : True if the password is correct, else False
    #     """
    #
    #     if self.hash_pass == pass_to_verif:
    #         return True
    #     else:
    #         return False

    # def connection(self, message: Message, addr):
    #     """
    #     Send connexion request while it receive no CONNECTED answer
    #     :return:
    #     None
    #     """
    #     if "pass" in message.content:
    #         if message.content["pass"] == self.hash_pass:
    #             self.client_port = addr[1]
    #             self.client_ip = addr[0]
    #             self.client_is_connected = True
    #             self.send('{"answer" : "CONNECTED"}', 2)
    #         else:
    #             print(addr)

    def start(self) -> None:
        self.run()

    def run(self) -> None:
        """
        Start the listener
        :return:
        None
        """
        self.is_running = True
        self.listen()

    def stop(self) -> None:
        """
        Stop the listener
        :return:
        None
        """
        self.is_running = False
        print(self.is_running)
        self.join()

    def send(self, message: str, message_id: Optional[int] = 0) -> None:
        """
        Send a message to the client
        :param message:
        The string to send
        :param message_id:
        The id of the message (default = 0)
        :return:
        None
        """
        data_to_send = Message(message_id, message)
        self.socket.sendto(bytes(str(data_to_send), 'utf-8'), (self.client_ip, self.client_port))
