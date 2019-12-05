# #!/bin/bash
sysctl net.ipv4.ip_forward=1

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
# # iptables -t nat -F

# drop all packets from 10.10.10.0/24 to 172.18.1.0/24 by default
# iptables -A FORWARD -s 10.10.10.0/24 -d 172.18.1.0/24 -j DROP


# forward icmp packets for debugging purposes
iptables -A FORWARD -s 10.10.10.0/24 -d 172.18.1.10   -p icmp --icmp-type echo-request -j ACCEPT
iptables -A FORWARD -s 10.10.10.0/24 -d 172.18.1.10   -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A FORWARD -s 172.18.1.10   -d 10.10.10.0/24 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A FORWARD -s 172.18.1.10   -d 10.10.10.0/24 -p icmp --icmp-type echo-reply -j ACCEPT

# accept incoming https connections and outgoing responses
iptables -A FORWARD -s 10.10.10.0/24 -d 172.18.1.10 -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 172.18.1.10 -d 10.10.10.0/24 -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# accept incoming http connections and outgoing responses
iptables -A FORWARD -s 10.10.10.0/24 -d 172.18.1.10 -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 172.18.1.10 -d 10.10.10.0/24 -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# maybe NAT ??
# forward port 80
# iptables -A PREROUTING -t nat -i eth1 -p tcp --dport 80 -j DNAT --to 172.18.1.10:8080
# iptables -A FORWARD -p tcp -d 172.18.1.10 --dport 8080 -j ACCEPT

# forward port 443
# iptables -A PREROUTING -t nat -i eth1 -p tcp --dport 443 -j DNAT --to 172.18.1.10:443
# iptables -A FORWARD -p tcp -d 172.18.1.10 --dport 443 -j ACCEPT

# iptables -t nat -A POSTROUTING  -s 172.18.1.0/24 -d 10.10.10.0/24 -j MASQUERADE

while [ true ]; do
	sleep 1000000 &
	wait $!
done
