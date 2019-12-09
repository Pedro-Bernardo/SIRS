FROM python:3.7-slim-buster

WORKDIR service

# RUN apk update && apk add --no-cache tcpdump socat python py2-pip git openssl nginx gcc musl-dev fcgiwrap spawn-fcgi python2-dev vim

COPY client client
# COPY client/requirements.txt ./

RUN apt-get update -y
RUN apt-get install iproute2 -y
RUN apt-get install iputils-ping -y 
RUN apt-get install curl -y
RUN apt-get install build-essential -y
RUN apt-get install python3-dev -y
RUN apt-get install libssl-dev -y
RUN apt-get install libffi-dev -y
RUN apt-get install vim -y
RUN apt-get install netcat -y

# RUN pip3 install -r client/requirements.txt --user
RUN pip3 install cryptography
RUN pip3 install pyopenssl
RUN pip3 install pycrypto
RUN pip3 install pycryptodome
RUN pip3 install requests
# RUN pip3 install pycrypto --user


# RUN pip3 install cryptography --user
# RUN pip3 install pyopenssl --user

# RUN mkdir ssl

# COPY ssl server/ssl

# # EXPOSE 8080
# EXPOSE 80
# EXPOSE 443

COPY launch.sh launch.sh
CMD ./launch.sh
# CMD tail -f /dev/null
