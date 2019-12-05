# #!/bin/sh

# set default gateway
ip route del default 
ip route add default via 172.18.1.254


# copy the provision file to /tmp and make the postgres user it's owner
cp /service/setup/create_the_tables.sql /tmp/
chown postgres /tmp/create_the_tables.sql

# cp /service/setup/postgresql.conf /etc/postgresql/10/main/postgresql.conf
service postgresql start


# cp /service/setup/postgresql.conf /etc/postgresql/10/main/postgresql.conf
# service postgresql stop
# service postgresql start
# export PATH=$PATH:/usr/local/go/bin

# su - postgres
sudo -u postgres psql -c "CREATE USER sirs WITH ENCRYPTED PASSWORD '1234';"
sudo -u postgres psql -c "CREATE DATABASE sirsdb OWNER sirs;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sirsdb TO sirs;"
sudo -u postgres $(export PGPASSWORD=1234 ; psql -h 127.0.0.1 -U sirs -d sirsdb < /tmp/create_the_tables.sql)


cp /service/setup/postgresql.conf /etc/postgresql/10/main/postgresql.conf
cp /service/setup/pg_hba.conf /etc/postgresql/10/main/pg_hba.conf

service postgresql restart
# service postgresql start


while [ true ]; do
	sleep 1000000 &
	wait $!
done


### MODIFICAR postgresql.conf -> ssl off, listen_addresses = '*' (maybe change later)
### MODIFICAR pg_hba.conf -> add entry host    all     all     all     md5 (maybe more a specific one?)
### TODO: setup ssl	

