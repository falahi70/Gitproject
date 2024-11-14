#!/bin/bash

DB_NAME="CoreInspect"
INTERVAL_MONTH="1 month"
INTERVAL_WEEK="1 week"

sudo -u postgres /usr/pgsql-15/bin/psql -d $DB_NAME <<EOF
DELETE FROM asset_inventory.service WHERE createdtime::timestamp < (NOW() - INTERVAL '$INTERVAL_MONTH');
DELETE FROM asset_inventory."cdromDrive" WHERE createdtime::timestamp < (NOW() - INTERVAL '$INTERVAL_MONTH');
EOF

