FROM ubuntu:latest

# RUN apt-get update && apt-get install -y iptables tcpdump
RUN apt-get update && apt-get install iptables iputils-ping iproute2 tcpdump -y

# tools
# RUN apt-get install -y nginx gcc libc6-dev python-dev npm nodejs vim

WORKDIR /root
# COPY Attack-Defense-Tools/ Attack-Defense-Tools/
# COPY Attack-Defense-Tools-private/ Attack-Defense-Tools-private/
# COPY setup.sh setup.sh
# RUN ./setup.sh

# firewall

# COPY team_router.rules /team_router.rules
# COPY org_router.rules /org_router.rules
COPY init.sh init.sh
CMD ./init.sh

# CMD tail -f /dev/null
