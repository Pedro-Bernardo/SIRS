#Instructions to build and run server:
`go build server.go`
`sudo ./server`

#Create Server TLS certificate and key
`openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout ssl/server.key -out ssl/server.crt`
