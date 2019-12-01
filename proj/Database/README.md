# USAGE
  
  
  For these steps run as postgres user
  
  1) Create user :  createuser < username >
  
  2) Create database: createdb -O < username > < dbname >
  
  3) Create schema : psql -h < ip > -U < username > < dbname > -c < create_the_tables.sql
  
  ===================
# TODO: implement sslmode=verify-full

# SSL=VERIFY-FULL

The env variable PGDATA should be set to the folder where **postgresql.conf** is
(windows i.e "C:\Program Files\PostgreSQL\12\data" by default)

add these lines to the config file
#### postgresql.conf
``` python
  ssl = on
  ssl_cert_file = < PATH TO **SERVER CERT** >
  ssl_key_file = < PATH TO **SERVER KEY** >
```

#### restart postgres server
```pg_ctl -D %PGDATA% < start/stop >```


 
documentation https://www.postgresql.org/docs/12/ssl-tcp.html
https://www.ibm.com/support/knowledgecenter/en/SSBRUQ_30.0.0/com.ibm.resilient.doc/dr/dr_postgres.htm

