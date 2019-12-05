FROM ubuntu:latest

WORKDIR service

RUN apt-get update && apt-get install iproute2 iputils-ping tcpdump postgresql sudo vim -y

COPY setup setup 


EXPOSE 5432

COPY launch.sh launch.sh
CMD ./launch.sh
# CMD tail -f /dev/null
