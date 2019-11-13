FROM ubuntu:latest

WORKDIR service

# RUN apk update && apk add --no-cache tcpdump socat python py2-pip git openssl nginx gcc musl-dev fcgiwrap spawn-fcgi python2-dev vim

RUN apt-get update && apt-get install iproute2 iputils-ping tcpdump -y

# RUN mkdir ssl

COPY server server 
# COPY ssl server/ssl

# EXPOSE 8080
EXPOSE 80
EXPOSE 443

COPY launch.sh launch.sh
CMD ./launch.sh
# CMD tail -f /dev/null
