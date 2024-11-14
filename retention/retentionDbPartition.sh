#!/bin/bash

DB_NAME="CoreInspect-Test"
SCHEMA_NAME="asset_inventory"
PARTITION_CUTOFF_DATE=$(date -d '12 month ago' +%Y-%m-%d)
FUTURE_MONTHS=4

TABLES=$(sudo -u postgres psql -d $DB_NAME -t -c "
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = '$SCHEMA_NAME'
      AND table_type = 'BASE TABLE'
      AND table_name NOT LIKE '%_20%';  -- Exclude partition tables
")

for TABLE in $TABLES; do
    TABLE=$(echo $TABLE | xargs) 
    echo "Processing table: $TABLE"

    if [[ $TABLE =~ [A-Z] || $TABLE =~ [^a-zA-Z0-9_] ]]; then
        TABLE="\"$TABLE\""
    fi

    PARTITIONS=$(sudo -u postgres psql -d $DB_NAME -t -c "
        SELECT inhrelid::regclass, pg_get_expr(c.relpartbound, c.oid) AS bound_expr
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class c ON i.inhrelid = c.oid
        WHERE inhparent = '$SCHEMA_NAME.$TABLE'::regclass;
    ")

    while IFS= read -r PARTITION_INFO; do
        PARTITION=$(echo $PARTITION_INFO | awk '{print $1}')
        BOUND_EXPR=$(echo $PARTITION_INFO | cut -d ' ' -f 2-)

        if [[ -z "$BOUND_EXPR" ]]; then
            echo "Skipping empty bound expression for partition: $PARTITION"
            continue
        fi

        FROM_DATE=$(echo $BOUND_EXPR | grep -oP "(?<=FROM \(')[^']*(?=')")
        TO_DATE=$(echo $BOUND_EXPR | grep -oP "(?<=TO \(')[^']*(?=')")

        if [[ -z "$TO_DATE" ]]; then
            echo "Skipping partition with empty TO_DATE: $PARTITION"
            continue
        fi

        FROM_DATE=$(date -d "$FROM_DATE" +%Y-%m-%d)
        TO_DATE=$(date -d "$TO_DATE" +%Y-%m-%d)

        if [[ $TO_DATE < $PARTITION_CUTOFF_DATE ]]; then
            echo "Dropping partition: $PARTITION with range: $FROM_DATE to $TO_DATE"
            sudo -u postgres psql -d $DB_NAME -c "DROP TABLE IF EXISTS $PARTITION;"
        fi
    done <<< "$PARTITIONS"

    for ((i = 0; i <= FUTURE_MONTHS; i++)); do
        PARTITION_START=$(date -d "+$i month" +%Y-%m-01)
        PARTITION_END=$(date -d "$PARTITION_START +1 month" +%Y-%m-01)
        PARTITION_NAME=$(echo "$TABLE" | tr -d '"' | sed "s/^${SCHEMA_NAME}\.//")_$(date -d "$PARTITION_START" +%Y_%m_%d)

        #if [[ $PARTITION_NAME =~ [A-Z] || $PARTITION_NAME =~ [^a-zA-Z0-9_] ]]; then
        #    PARTITION_NAME="\"$PARTITION_NAME\""
        #fi


        EXISTS=$(sudo -u postgres psql -d $DB_NAME -t -c "
              SELECT to_regclass('$SCHEMA_NAME.$PARTITION_NAME');
              " | xargs)


        if [[ -z "$EXISTS" || "$EXISTS" == "NULL" ]]; then
            echo "Creating partition: $SCHEMA_NAME.$PARTITION_NAME with range: $PARTITION_START to $PARTITION_END"
            sudo -u postgres psql -d $DB_NAME -c "
                CREATE TABLE $SCHEMA_NAME.$PARTITION_NAME PARTITION OF $SCHEMA_NAME.$TABLE
                FOR VALUES FROM ('$PARTITION_START') TO ('$PARTITION_END');
            "
        fi
    done
done

