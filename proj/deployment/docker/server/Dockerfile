# FROM ubuntu:latest
FROM python:3.7-slim-buster

WORKDIR service

# RUN apk update && apk add --no-cache tcpdump socat python py2-pip git openssl nginx gcc musl-dev fcgiwrap spawn-fcgi python2-dev vim

RUN apt-get update && apt-get install iproute2 iputils-ping tcpdump vim git -y
RUN apt-get install build-essential -y
RUN apt-get install python3-dev -y
RUN apt-get install libssl-dev -y
RUN apt-get install libffi-dev -y
RUN pip3 install pycrypto
# RUN mkdir ssl

COPY server server 
ENV PATH="${PATH}:/usr/local/go/bin/"
ENV GOPATH="/service/server"
ENV SSL_DIR="/service/server/ssl"

# COPY ssl server/ssl

# EXPOSE 8080
EXPOSE 80
EXPOSE 443

COPY launch.sh launch.sh
CMD ./launch.sh
# CMD tail -f /dev/null
