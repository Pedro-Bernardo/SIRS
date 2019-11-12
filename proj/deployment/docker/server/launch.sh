# #!/bin/ash

# export TEAM_ID="$(ip a | grep "inet 17" | sed -En "s/.*inet 172\.[0-9]+\.([0-9]+)\..*/\1/p")"
# ip r add 172.18.0.0/16 via 172.18.$TEAM_ID.254
# ip r add 172.16.0.0/16 via 172.18.$TEAM_ID.254

# # Start the primary process and put it in the background

# socat -d -d TCP-LISTEN:8080,reuseaddr,fork EXEC:"./exampleServices/speedrun-004" &

# socat -d -d TCP-LISTEN:8081,reuseaddr,fork EXEC:"/bin/sh" &

# ( cd exampleServices/the-tangle/src && ./run.sh ) &

# python exampleServices/service1.py &

# if [ ! -z "$CAPTURE" ]
# then
# 	tcpdump -i eth0 -w /pcaps/output.pcap
# fi

# wait %1
