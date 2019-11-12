FROM alpine:3.10

WORKDIR services

RUN mkdir exampleServices

# RUN apk update && apk add --no-cache tcpdump socat python py2-pip git openssl nginx gcc musl-dev fcgiwrap spawn-fcgi python2-dev vim

# COPY requirements/requirements.txt requirements.txt
# RUN pip install -r requirements.txt

# RUN apk del gcc python2-dev py2-pip

# COPY exampleServices/ exampleServices/

# RUN /bin/ash -c 'cd /services/exampleServices/the-tangle/src && ./setup.sh'

#ENV FLASK_APP=exampleServices/service1.py

#CMD socat -u tcp-l:7777,fork system:./speedrun-004 & 

# EXPOSE 8080
# EXPOSE 8081
# EXPOSE 5000
# EXPOSE 4563

COPY launch.sh launch.sh
CMD ./launch.sh
