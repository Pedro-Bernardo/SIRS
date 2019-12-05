#!/bin/dash

# generate certs
# copy certs
# add to docker
# build images
# compose up
# pritn command to execute client

mkdir -p cacerts && cd cacerts

echo "generating CA keys"
# openssl req -new -newkey rsa:2048 -nodes -out ca.csr -keyout ca.key
openssl genrsa -out ca.key 2048

echo "creating self-signed certifiate"
openssl req -new -x509 -key ca.key -out ca.crt
# openssl x509 -trustout -signkey ca.key -days 365 -req -in ca.csr -out ca.pem

cd ..

echo "creating server_tls key"
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server_tls.key

echo "creating server_tls signing request"
openssl req -new -key server_tls.key -out server_tls.csr

echo "creating server_tls ceritficate signed by the CA"
openssl x509 -req -in server_tls.csr -CA cacerts/ca.crt -CAkey cacerts/ca.key -CAcreateserial -extfile ./openssl.cnf -extensions v3_ca -out server_tls.crt -days 300 -sha256

echo "creating server key"
# openssl genrsa -out server.key 2048
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key

echo "creating server signing request"
openssl req -new -key server.key -out server.csr

echo "creating server ceritficate signed by the CA"
openssl x509 -req -in server.csr -CA cacerts/ca.crt -CAkey cacerts/ca.key -CAcreateserial -extfile ./openssl.cnf -extensions v3_ca -out server.crt -days 300 -sha256

# openssl x509 -req -in server_tls.csr -CA cacerts/ca.pem -CAkey cacerts/ca.key -CAcreateserial -out server_tls.crt -days 300 -sha256


echo "moving CA certificate to client"
mkdir -p ../Client/ssl && cp cacerts/ca.crt server.crt ../Client/ssl
echo "moving keys to server"
mkdir -p ../Server/ssl && cp server_tls.key server_tls.crt server.key server.crt ../Server/ssl

echo "copying files to docker images"
mkdir -p docker/client/client/ && cp -r ../Client/client ../Client/ssl docker/client/client/
mkdir -p docker/server/server/ && cp -r ../Server/pkg ../Server/src ../Server/ssl ../Server/bin docker/server/server/

cd docker

# for i in $(ls -d */); do 
#     # remove "/" form directory name
#     directory_name=$(echo $i | rev | cut -c 2- | rev)
#     echo "creating container for $directory_name" 
#     cd $i && docker build . --tag=$directory_name && cd ..
# done

# docker-compose up -d

# client_pid=$(docker ps | grep client | cut -d' ' -f1)
# echo "setup complete!"
# echo "run the following command to enter to the client container: "
# echo "docker exec -it $client_pid bash"

