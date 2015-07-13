#! /bin/bash -e

if (( $# != 1 ))
then

    echo "usage: $0 yaml_file"
    exit 99;

else

    DBNAME=`python -m rtapebbletest.configwrapper $1 database_name`
    DBUSER=`python -m rtapebbletest.configwrapper $1 database_user`

    sudo -u postgres dropdb --if-exists $DBNAME
    sudo -u postgres createdb --owner $DBUSER $DBNAME
    sudo -u postgres createlang plpythonu $DBNAME
    sudo -u postgres psql --quiet -d $DBNAME -c 'create extension "hstore";'
    sudo -u postgres psql --quiet -d $DBNAME -c 'create extension "uuid-ossp";'
    sudo -u postgres psql --quiet -d $DBNAME -c 'create extension "pgcrypto";'
    sudo -u postgres psql --quiet -d $DBNAME -c 'create extension "citext";'
    sudo -u postgres psql --quiet -d $DBNAME -c "create extension btree_gist;"
    sudo -u postgres psql --quiet -d $DBNAME -c "create extension ltree;"

    echo "Now run python upgrade_database.py $1"

fi
