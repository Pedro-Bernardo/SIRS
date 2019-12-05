#!/bin/dash

# generate certs
# copy certs
# add to docker
# build images
# compose up
# pritn command to execute client

mkdir -p cacerts && cd cacerts

echo "generating CA keys"
openssl req -new -newkey rsa:2048 -nodes -out ca.csr -keyout ca.key

echo "creating self-signed certifiate"
openssl x509 -trustout -signkey ca.key -days 365 -req -in ca.csr -out ca.pem
cd ..

echo "creating server key"
openssl genrsa -out server_tls.key 2048

echo "creating server signing request"
openssl req -new -key server_tls.key -out server_tls.csr

echo "creating server ceritficate signed by the CA"
openssl x509 -req -in server_tls.csr -CA cacerts/ca.pem -CAkey cacerts/ca.key -CAcreateserial -out server_tls.crt -days 300 -sha256

echo "moving CA certificate to client"
cp cacerts/ca.pem ../Client/ssl
echo "moving keys to server"
cp server_tls.key server_tls.crt ../Server/ssl

echo "copying files to docker images"
cp -r ../Client/client ../Client/ssl docker/client/client/
cp -r ../Server/pkg ../Server/src ../Server/ssl ../Server/bin docker/server/server/

cd docker

for i in $(ls -d */); do 
    # remove "/" form directory name
    directory_name=$(echo $i | rev | cut -c 2- | rev)
    echo "creating container for $directory_name" 
    cd $i && docker build . --tag=$directory_name && cd ..
done

docker-compose up -d

client_pid=$(docker ps | grep client | cut -d' ' -f1)
echo "setup complete!"
echo "run the following command to enter to the client container: "
echo "docker exec -it $client_pid bash"

