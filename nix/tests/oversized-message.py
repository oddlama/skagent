"""Announce an agent message far above the size limit, then report whether
the agent hung up ("closed") or kept waiting for the rest ("open")."""

import socket
import struct
import sys

agent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
agent.connect(sys.argv[1])
agent.settimeout(5)
agent.sendall(struct.pack(">I", 0xFFFFFFFF) + bytes(4096))
try:
    reply = agent.recv(1)
except socket.timeout:
    print("open")
except ConnectionResetError:
    print("closed")
else:
    print("closed" if reply == b"" else "answered")
