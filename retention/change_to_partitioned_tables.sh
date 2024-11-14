#!/bin/bash

DB_NAME="CoreInspect-Test"
SCHEMA_NAME="asset_inventory"
TABLE_NAME="bios"

# Get the current year and month
CURRENT_YEAR=$(date +%Y)
CURRENT_MONTH=$(date +%m)

# Loop through the last 12 months
for i in {12..1}; do
    START_DATE=$(date -d "$CURRENT_YEAR-$CURRENT_MONTH-01 - $i month" +%Y-%m-%d)
    END_DATE=$(date -d "$START_DATE + 1 month" +%Y-%m-%d)
    PARTITION_NAME="${TABLE_NAME}_$(date -d "$START_DATE" +%Y_%m)"
    
    echo "Creating partition: $PARTITION_NAME from $START_DATE to $END_DATE"

    sudo -u postgres psql -d $DB_NAME -c "
    CREATE TABLE $SCHEMA_NAME.$PARTITION_NAME PARTITION OF $SCHEMA_NAME.$TABLE_NAME
    FOR VALUES FROM ('$START_DATE') TO ('$END_DATE');
    "
done

