# import json
#
# my_dict = {"protocols_available": ["1.0", "1.1", "2.0"], "authentication_required": "yes"}
# the_json = json.dumps(my_dict)
# result = json.loads(the_json)
# the_json = str.encode(the_json, "utf8")
# print(the_json)
# print(type(result.keys()))


import os
import base64

a = base64.b64encode(b'test').decode("ascii")
b = base64.b64decode(a)

print(len(a))
print(len(b))
print(b)
