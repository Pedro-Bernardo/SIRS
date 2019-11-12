FROM alpine:latest

RUN addgroup -S the-tangle && adduser -S the-tangle -G the-tangle && apk update && apk add git git-daemon openssl nginx fcgiwrap spawn-fcgi python2 python2-dev py2-pip gcc libc-dev && pip install gitpython PyCrypto && apk del python2-dev py2-pip gcc libc-dev && rm -rf /var/cache/apk/* && ln -s /usr/libexec/git-core/ /usr/lib/git-core

COPY src/nginx.conf src/run.sh /srv/the-tangle/

RUN mkdir -p /srv/the-tangle/api && cd /srv/the-tangle/api/ && git init --bare --shared && git config --add http.receivepack true && chown -R the-tangle:the-tangle /srv/the-tangle && chmod 700 /srv/the-tangle/api -R

ADD src/hooks /srv/the-tangle/api/hooks

WORKDIR /srv/the-tangle/

EXPOSE 4563

VOLUME ["/srv/the-tangle"]

CMD source ./run.sh
