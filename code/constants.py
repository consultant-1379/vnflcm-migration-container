#!/usr/bin/env python3

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


# log file path
log_path = "/vnflcm-ext/log/migration/"
log_file_path = "/vnflcm-ext/log/migration/logfile.log"

instances_path = "/vnflcm-ext/current/vnf_instances"

# migration script's path
main_dir = "/opt/ericsson/eric-vnflcm-migration/scripts"
restore_service = "/opt/ericsson/eric-vnflcm-migration/scripts/restoreservice.py"
restore_db = "/opt/ericsson/eric-vnflcm-migration/scripts/restoredb.py"
state_file = "/vnflcm-ext/state_file.json"
nfvo_and_vnfm_update = "/opt/ericsson/eric-vnflcm-migration/scripts/nfvoupdate.py"
vmvnfm_health_check = "/opt/ericsson/eric-vnflcm-migration/scripts/healthCheckScript.py"
retriveusers = "/opt/ericsson/eric-vnflcm-migration/scripts/retriveusers.py"
pollingagent = "/opt/ericsson/eric-vnflcm-migration/scripts/pollingagent.py"
camunda_uplift_script = "/opt/ericsson/eric-vnflcm-migration/scripts/camunda_uplift_script.sql"
vnflafdb_upgrade_script = "/opt/ericsson/eric-vnflcm-migration/scripts/vnflafdb_upgrade_script.sql"
wfsdb_upgrade_script = "/opt/ericsson/eric-vnflcm-migration/scripts/wfsdb_upgrade_script.sql"