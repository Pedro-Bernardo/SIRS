# #!/bin/sh

# set default gateway
ip route del default 
ip route add default via 10.10.10.10

while [ true ]; do
	sleep 1000000 &
	wait $!
done