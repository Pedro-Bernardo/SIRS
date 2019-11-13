# #!/bin/sh

# set default gateway
ip route del default 
ip route add default via 172.18.1.254

# iptables -P FORWARD ACCEPT
# iptables -F FORWARD
# iptables -t nat -F
# iptables -t nat -A POSTROUTING  -o ens9 -j MASQUERADE

cd /service/server/src/server && ./go_server