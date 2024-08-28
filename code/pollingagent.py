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

import json
import os
import subprocess
import time
import sys
import constants
from vnflcmlog import VnfLcmLog


class PollingAgent:

    def __init__(self):
        self.log = VnfLcmLog("PollingAgent")
        self.loc_admin_conf = sys.argv[1]
        self.pod_namespace = sys.argv[2]
        self.service_0_pod = sys.argv[3]
        self.kube_cmd = "kubectl --kubeconfig={} -n {}".format(self.loc_admin_conf, self.pod_namespace)
        self.check_db_restore_script_running = ['pgrep -f .*python3.restoredb.py']
        self.check_svc_restore_script_running = ['pgrep -f .*python3.restoreservice.py']
        self.check_nfvo_restore_script_running = ['pgrep -f .*python3.nfvoupdate.py']
        self.db_param_state_file = "db_restore"
        self.svc_param_state_file = "svc_restore"
        self.nfvo_param_state_file = "nfvo_update"

    def get_master_db(self):
        try:
            self.log.info("Checking for the master db")
            master_db_cmd = "{} get pods -L role | grep -i eric-vnflcm-db | grep -i master | cut -d ' ' -f1".format(self.kube_cmd)
            self.master_db = subprocess.check_output([master_db_cmd], shell=True).strip().decode()
            self.log.info("Master db is found. Proceeding with the execution of script")
        except Exception as err:
            print(("Exception in finding master db:: {}".format(str(err))))
            self.log.error("Exception in finding master db:: {}".format(str(err)))
            exit(1)

    def read_status_file(self):
        try:
            self.log.info("Polling Agent script execution has started")
            # When running in loop, value would chnage so adding the open() here.
            with open(constants.state_file) as file:
                data = json.load(file)
            self.db_restore_status = data["db_restore"]
            self.svc_restore_status = data["svc_restore"]
            self.nfvo_update_status = data["nfvo_update"]
            self.healthcheckscript = data["health_check"]
            self.get_master_db()
            # Reading the status file.
            read_db_state_file = ("{} exec {} -c eric-vnflcm-db -- cat /tmp/.restoreVnflcmDb.txt |cut -d ':' -f2| tail -1 ").format(self.kube_cmd, self.master_db)
            read_svc_state_file = ("{} exec {} -c eric-vnflcm-service -- cat /vnflcm-ext/.restoreVnflcmService.txt |cut -d ':' -f2| tail -1").format(self.kube_cmd, self.service_0_pod)
            read_nfvo_state_file = ("{} exec {} -c eric-vnflcm-service -- cat /vnflcm-ext/.restoreVnflcmService.txt | awk '/nfvo_update/' |cut -d ':' -f2").format(self.kube_cmd, self.service_0_pod)
            db_status_file_exists = ("{} exec {} -c eric-vnflcm-db --  [ -f /tmp/.restoreVnflcmDb.txt ] >/dev/null 2>&1").format(self.kube_cmd, self.master_db)
            svc_status_file_exists = ("{} exec {} -c eric-vnflcm-service --  [ -f /vnflcm-ext/.restoreVnflcmService.txt ] >/dev/null 2>&1").format(self.kube_cmd, self.service_0_pod)

            # Assign values to the update_pod_status()
            db_status = self.update_pod_status(self.db_restore_status, read_db_state_file, self.check_db_restore_script_running, data, self.db_param_state_file, db_status_file_exists)
            if db_status:
                self.log.info("DB pod status updated")
                svc_status = self.update_pod_status(self.svc_restore_status, read_svc_state_file, self.check_svc_restore_script_running, data, self.svc_param_state_file, svc_status_file_exists)
                if svc_status:
                    self.log.info("Service pod status updated")
                    nfvo_status = self.update_pod_status(self.nfvo_update_status, read_nfvo_state_file, self.check_nfvo_restore_script_running, data, self.nfvo_param_state_file, svc_status_file_exists)
                    self.log.info("Nfvo status updated")
        except Exception as err:
            print(("Exception in reading status file:: {}".format(str(err))))
            self.log.error("Exception in reading status file:: {}".format(str(err)))
            exit(1)

    def update_pod_status(self, status, exec_to_read_status, check_script_running, data, param_state_file, status_file_exists):
        try:
            self.log.info("Updating pod status, status:: {}, param_state_file:: {}".format(status, param_state_file))
            process = subprocess.Popen(check_script_running, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            my_pid, err = process.communicate()
            if len(my_pid.splitlines()) != 0 and status != "":
                self.log.info("Status for {} is not null".format(param_state_file))
                status_file_exists_value = os.system(status_file_exists)
                if status_file_exists_value == 0:
                    value = subprocess.check_output([exec_to_read_status], shell=True).decode()
                    data[param_state_file] = value.strip()
                    with open(constants.state_file, 'w') as json_file:
                        json.dump(data, json_file)
            elif status != "Success" and status != "Failed":
                self.log.info("Status of {} is not equal to Success & Failed".format(param_state_file))
                status_file_exists_value = os.system(status_file_exists)
                if status_file_exists_value == 0:
                    value = subprocess.check_output([exec_to_read_status], shell=True).decode()
                    data[param_state_file] = value.strip()
                    with open(constants.state_file, 'w') as json_file:
                        json.dump(data, json_file)
            elif status == "Failed":
                self.log.info("Status of {} is equal to Failed".format(param_state_file))
                status_file_exists_value = os.system(status_file_exists)
                if status_file_exists_value == 0:
                    value = subprocess.check_output([exec_to_read_status], shell=True).decode()
                    data[param_state_file] = value.strip()
                    with open(constants.state_file, 'w') as json_file:
                        json.dump(data, json_file)
            elif status == "Success":
                self.log.info("The status of {} is successful".format(param_state_file))
                return True
        except Exception as err:
            print(("Exception in updating pod status:: {}".format(str(err))))
            self.log.error("Exception in updating pod status:: {}".format(str(err)))
            exit(1)


def main():
    pollingAgent = PollingAgent()
    while True:
        pollingAgent.read_status_file()
        time.sleep(5)


if __name__ == '__main__':
    main()
