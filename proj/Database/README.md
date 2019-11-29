# USAGE
  
  
  For these steps run as postgres user
  
  1) Create user :  createuser <username>
  
  2) Create database: createdb -O user <dbname>
  
  3) Create schema : psql -h <ip> -U <username> <dbname> -c < create_the_tables.sql
