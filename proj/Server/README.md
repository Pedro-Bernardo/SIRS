#Instructions to build and run server:
`go build server.go`
`sudo ./server`

# Create Server TLS certificate and key
`openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout ssl/server_tls.key -out ssl/server_tls.crt`

# Create CA
mkdir cacerts && cd cacerts
# create CA private key and signing reques
openssl req -new -newkey rsa:2048 -nodes -out ca.csr -keyout ca.key  
# create the self-signed ca certificate
openssl x509 -trustout -signkey ca.key -days 365 -req -in ca.csr -out ca.pem  

cd ..
# crate server key
openssl genrsa -out server.key 2048
# create server certificate signing request
openssl req -new -key server.key -out server.csr
# create the server certificate signed by the ca
openssl x509 -req -in server.csr -CA cacerts/ca.pem -CAkey cacerts/ca.key -CAcreateserial -out server.crt -days 300 -sha256

cp cacerts/ca.pem ../Client/ssl
cp server.key server.crt ../Server/ssl
