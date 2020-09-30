from functools import reduce
import json
from typing import Union, Optional
import hashlib


class Message:

    def __init__(self, message_id: int, message: str) -> None:
        """
        Creat a new Message
        :param message_id:
        Id of the message
        :param message:
        Content of the message
        """
        self.parity_check = lambda msg: reduce(lambda x, y: int(x) ^ int(y),
                                               "".join([bin(msg[i])[2:] for i in range(len(msg))]), 0)
        self.id = message_id
        self.len = len(message)
        self.parity = self.parity_check(bytes(message, "utf8"))
        self.message = message
        self.content = dict()

    def verif(self) -> bool:
        """
        Check if the message is corrupted
        :return:
        Bool (True if not corrupted, else False)
        """
        if self.parity_check(bytes(self.message, "utf8")) != self.parity:
            return False
        elif len(self.message) != self.len:
            return False
        else:
            return True

    @staticmethod
    def from_json(data_string: str):
        """
        Check if the received message can be transform in a Message object, if it is possible, return
        a Message containing the received data, if it failed it return None
        :return:
        A Message object
        """
        message = Message(0, "")
        try:

            json_dict = json.loads(data_string)
            message.import_json(json_dict)
            if message.verif():
                return message
            else:
                return None
        except:
            return None

    def import_json(self, json_in):
        """
        If it is possible, load the data of a Json string into the Message object
        :param json_in:
        The Json to read
        :return:
        None
        """
        if "id" in json_in and "parity" in json_in and "len" in json_in and "message" in json_in:
            self.id = json_in["id"]
            self.parity = json_in["parity"]
            self.len = json_in["len"]
            self.message = json_in["message"]
            self.content = json.loads(self.message)

    def __iter__(self) -> Union[int, str]:
        yield "id", self.id
        yield "parity", self.parity
        yield "len", self.len
        yield "message", self.message

    def __str__(self) -> str:
        """
        Convert the message to a Json object
        :return:
        str : the Json object
        """
        return json.dumps(dict(self))

    @staticmethod
    def creat_connection_message(password: str, verbose: Optional[int] = 1, hash_pass: Optional[bool] = False) -> str:
        if hash_pass:
            hash_password = hashlib.sha1(bytes(password, "utf8")).hexdigest()
        else:
            hash_password = password

        return '{"password": "' + str(hash_password) + '" , "verbose": ' + str(verbose) + '}'

    @staticmethod
    def spe_creat_connection_message(password: str, port: Optional[int] = 50000,
                                     hash_pass: Optional[bool] = False) -> str:
        """
        Create an old version of connection message to connect to Clovis Mini
        :return:
        A message that will be understood in the old software of Clovis Mini
        """
        if hash_pass:
            hash_password = hashlib.sha1(bytes(password, "utf8")).hexdigest()
        else:
            hash_password = password

        return '{"port" : ' + str(port) + ', "pass" : "' + str(hash_password) + '"}'

    @staticmethod
    def is_message(data_string: str):
        """
        Check if the received message is a Message object.
        :return:
        True if it is a Message object else False
        """
        return not Message.from_json(data_string) is None
