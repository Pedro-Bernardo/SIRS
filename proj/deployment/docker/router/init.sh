# #!/bin/bash

# TEAM_ID_AUTO="$(ip a | grep "inet 17" | head -n 1 | sed -En "s/.*inet 172\.[0-9]+\.([0-9]+)\..*/\1/p")"
# export TEAM_ID="${TEAM_ID:-$TEAM_ID_AUTO}"

# (
# cd /
# test "$TEAM_ID" = "0" && cp org_router.rules iptables.rules || cp team_router.rules iptables.rules
# sed -i "s/TEAM_ID/$TEAM_ID/g" iptables.rules

# iptables-restore iptables.rules
# )

# if [ "$TEAM_ID" = "0" ]; then
# 	for TEAM in $(seq 1 $N_TEAMS); do
# 		echo "Add routes for team $TEAM"
# 		ip r add 172.18.$TEAM.0/24 via 172.16.$TEAM.2
# 	done
# else
# 	echo "Add route to other teams"
# 	ip r add 172.18.0.0/16 via "172.16.$TEAM_ID.254"
# fi

# # just do something to not shutdown
# cleanup () {
# 	kill -s SIGTERM $!
# 	exit 0
# }

# trap cleanup SIGINT SIGTERM

# while [ true ]; do
# 	sleep 1000000 &
# 	wait $!
# done
