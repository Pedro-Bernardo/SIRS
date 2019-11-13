FROM alpine:3.10.3

WORKDIR services

# RUN mkdir exampleServices

RUN apk update && apk add --no-cache openrc nginx 
RUN adduser -D -g 'www' www
RUN mkdir /www
RUN chown -R www:www /var/lib/nginx
RUN chown -R www:www /www
RUN rc-service nginx start

# COPY requirements/requirements.txt requi
COPY launch.sh launch.sh
CMD ./launch.sh