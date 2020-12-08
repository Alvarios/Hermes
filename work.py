# import json
#
# my_dict = {"protocols_available": ["1.0", "1.1", "2.0"], "authentication_required": "yes"}
# the_json = json.dumps(my_dict)
# result = json.loads(the_json)
# the_json = str.encode(the_json, "utf8")
# print(the_json)
# print(type(result.keys()))


# import os
# import base64
#
# a = base64.b64encode(b'test').decode("ascii")
# b = base64.b64decode(a)
#
# print(len(a))
# print(len(b))
# print(b)

from hermes.security.Handshake import Handshake
from hermes.security.utils import derive_password_scrypt
import os

allowed_authentication_methods = ["password"]
password_to_derive = b"test"
password_salt = os.urandom(16)
password_client = b"test"
derived_password = derive_password_scrypt(password_salt=password_salt, password_to_derive=password_to_derive)

authentication_information_server = {
    "password": {Handshake.PASSWORD_AUTH_METHOD_DERIVED_PASSWORD_KEY: derived_password,
                 Handshake.PASSWORD_AUTH_METHOD_SALT_KEY: password_salt}}
authentication_information_client = {Handshake.PASSWORD_AUTH_METHOD_PASSWORD_KEY: password_client}
authentication_information_client = None
if allowed_authentication_methods[0] == "custom":
    authentication_information_client = {"test": "retest", "foo": "bar"}

server = Handshake(role=Handshake.SERVER, authentication_information=authentication_information_server,
                   allowed_authentication_methods=allowed_authentication_methods)

client = Handshake(role=Handshake.CLIENT, authentication_information=authentication_information_client,
                   allowed_authentication_methods=allowed_authentication_methods)

connection_request = client.next_message()
print(int.from_bytes(connection_request.topic, 'little'))
print(connection_request.to_bytes())
server.add_message(connection_request)

server_pub_key = server.next_message()
print(int.from_bytes(server_pub_key.topic, 'little'))
print(server_pub_key.to_bytes())
client.add_message(server_pub_key)

client_pub_key = client.next_message()
print(int.from_bytes(client_pub_key.topic, 'little'))
print(client_pub_key.to_bytes())
server.add_message(client_pub_key)

auth_required = server.next_message()
print(int.from_bytes(auth_required.topic, 'little'))
print(auth_required.to_bytes())
client.add_message(auth_required)

auth_info = client.next_message()
print(int.from_bytes(auth_info.topic, 'little'))
print(auth_info.to_bytes())
server.add_message(auth_info)
if allowed_authentication_methods[0] == "custom":
    if server.get_authentication_information() == authentication_information_client:
        server.approve()
    else:
        server.disapprove()

co_status = server.next_message()
print(int.from_bytes(co_status.topic, 'little'))
print(co_status.to_bytes())
client.add_message(co_status)

print(client.get_status())
print(server.get_status())
