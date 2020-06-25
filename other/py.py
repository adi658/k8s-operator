import base64

message = "Python is fun"
message_bytes = message.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
print(base64_bytes)
print(str(base64_bytes,'utf-8'))
base64_message = base64_bytes.decode('ascii')

# print(base64_message)