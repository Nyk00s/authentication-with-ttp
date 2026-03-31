import socket
import json


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9001))

s.send((json.dumps({"action": "something"}) + '\n').encode())

print(json.loads(s.recv(1024).decode()))
