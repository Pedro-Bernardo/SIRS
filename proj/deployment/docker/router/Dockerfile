FROM alpine:3.10

# RUN apt-get update && apt-get install -y iptables tcpdump
RUN apk update && apk add --no-cache tcpdump iptables

# tools
# RUN apt-get install -y nginx gcc libc6-dev python-dev npm nodejs vim

WORKDIR /root
# COPY Attack-Defense-Tools/ Attack-Defense-Tools/
# COPY Attack-Defense-Tools-private/ Attack-Defense-Tools-private/
# COPY setup.sh setup.sh
# RUN ./setup.sh

# firewall
# COPY init.sh /init
# COPY team_router.rules /team_router.rules
# COPY org_router.rules /org_router.rules

# CMD /init
