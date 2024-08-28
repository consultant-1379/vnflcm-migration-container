#!/bin/sh
# ********************************************************************
# Ericsson LMI                                    SCRIPT
# ********************************************************************
#
# (c) Ericsson LMI 2020 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson LMI. The programs may be used and/or copied only with
# the written permission from Ericsson LMI or in accordance with the
# terms and conditions stipulated in the agreement/contract under
# which the program(s) have been supplied.
#
# ********************************************************************
# Name    : entrypoint.sh
# Revision: 1.0
# Purpose : Initial configuration while booting migration container
#
# Usage   : sh entrypoint.sh
#
# ********************************************************************

function adp_log() {

   local __level__=$1
   local msg=$2
   msg="$(echo "$msg" | sed 's|"|\\"|g' | tr -d '\n')"
   service_version=`echo $SERVICE_VERSION | awk -F'-|+' '{print $1}'`
   printf '{"version": "%s", "timestamp": "%s", "severity": "%s", "service_id": "%s", "message": "%s"}\n' "$service_version" "$(date --iso-8601=seconds)" "$__level__" "$SERVICE_ID" "$msg"
}



adp_log INFO "Starting to run entrypoint script..."

#Give permissions for vnflcm-ext directory for non-root user to work
#chmod -R 777 /vnflcm-ext/

#log path dir creation.
mkdir -p /vnflcm-ext/log/migration
#chmod -R 777 /vnflcm-ext/log/

if [ ! -f /vnflcm-ext/log/migration/logfile.log ] ; then
   adp_log INFO "Log file created successfully."
   touch /vnflcm-ext/log/migration/logfile.log
else
   adp_log INFO "Log file is already created."
fi
# Give permissions to newly created file
#chmod -R 777 /vnflcm-ext/log/

#State file creation in vnflcm-ext.
if [ ! -f /vnflcm-ext/state_file.json ] ; then
    echo '{"health_check": "", "nfvo_update": "", "svc_restore": "", "db_restore": ""}' > /vnflcm-ext/state_file.json
else
    adp_log INFO "State file is already present."
fi

#chmod -R 777 /vnflcm-ext/state_file.json

# Create soft-link to keep same usage post py uplift
#ln -f -s /usr/bin/python3.6 /usr/bin/python

# This will ensure that entry point will not exit.
while true
    do
        sleep 300s
    done
