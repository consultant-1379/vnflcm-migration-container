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
import time
import subprocess
import sys
import os
import requests
import configparser
import signal
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import constants
from vnflcmlog import VnfLcmLog


class Migration:

    def __init__(self, file_path):

        self.log = VnfLcmLog("Migration")
        global parser
        parser = configparser.ConfigParser()
        parser.read(file_path)
        self.loc_admin_conf = parser.get('MigrationInput', 'Admin_Conf_Location')
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.is_nfvo = parser.get('MigrationInput', 'NFVO')
        #self.eo_host = parser.get('MigrationInput', 'EO_Host')
        #self.eo_user_passwd = parser.get('MigrationInput', 'EO_USER_Passwd')
        #self.eo_user = parser.get('MigrationInput', 'EO_User')
        self.enm_host = parser.get('MigrationInput', 'ENM_HOST')
        self.enm_admin_user = parser.get('MigrationInput', 'ENM_ADMIN_USER')
        self.enm_admin_user_passwd = parser.get('MigrationInput', 'ENM_ADMIN_USER_PASSWD')
        self.db_backup_tar_location = parser.get('MigrationInput', 'DB_Backup_Tar_Location')
        self.services_backup_tar_location = parser.get('MigrationInput', 'Services_Backup_Tar_Location')
        self.evnfm_host = parser.get('MigrationInput', 'EVNFM_HOST')
        self.evnfm_user_name = parser.get('MigrationInput', 'EVNFM_User')
        self.evnfm_user_password = parser.get('MigrationInput', 'EVNFM_Passwd')
        self.evnfm_super_user_name = parser.get('MigrationInput', 'EVNFM_Super_User')
        self.evnfm_super_user_password = parser.get('MigrationInput', 'EVNFM_Super_Passwd')
        #self.eo_admin_tenant = parser.get('MigrationInput', 'EO_ADMIN_Tenant')
        self.grant_type = "password"
        self.client_id = "admin-cli"
        self.role = "E-VNFM Super User Role"

    # Validating each parameter of input file
    def validation_of_user_input_file(self):
        self.log.info("Validating user input file")
        try:
            if self.db_backup_tar_location == "" or self.services_backup_tar_location == "" or self.evnfm_host == "" or self.evnfm_user_name == "" or self.evnfm_user_password == "" or self.evnfm_super_user_name == "" or self.evnfm_super_user_password == "":
                if self.db_backup_tar_location == "" or self.services_backup_tar_location == "":
                    if self.db_backup_tar_location == "":
                        self.db_backup_tar_location = "/tmp/mig_data"
                        print(("DB_Backup_Tar_Location is null, proceeding with default location",
                              self.db_backup_tar_location))
                        self.log.info("DB_Backup_Tar_Location is null, proceeding with default location {}".format(
                            self.db_backup_tar_location))
                    if self.services_backup_tar_location == "":
                        self.services_backup_tar_location = "/vnflcm-ext/mig_data"
                        print(("Services_Backup_Tar_Location is null, proceeding with default location",
                              self.services_backup_tar_location))
                        self.log.info(
                            "Services_Backup_Tar_Location is null, proceeding with default location {}".format(
                                self.services_backup_tar_location))
                else:
                    print("Parameters value in migration.ini file shouldn't be empty,please fill in proper values.")
                    self.log.error(
                        "Parameters value in migration.ini file shouldn't be empty,please fill in proper values.")
                    self.delete_ini_file()
                    exit(1)
            elif not os.path.exists(self.loc_admin_conf):
                print(("Unable to find admin config file under ", self.loc_admin_conf))
                self.log.error("Unable to find admin config file under {}".format(self.loc_admin_conf))
                self.delete_ini_file()
                exit(1)
            else:
                if self.is_nfvo.lower() == "true":
                    self.log.info("This is a full stack migration")
                    print("This is a full stack migration")
                elif self.is_nfvo.lower() == "false":
                    self.log.info("This is a small stack migration")
                    print("This is a small stack migration")
                else:
                    print("NFVO parameter must be either true or false")
                    self.log.error("NFVO parameter must be either true or false")
                    self.delete_ini_file()
                    exit(1)
        except Exception as ex:
            self.log.exception("exception in validating migration.ini file:: {}".format(ex))
            print("exception in validating migration.ini file")
            self.delete_ini_file()
            exit(1)

    # Fetch namespace form the POD ENV and set kube_cmd
    def get_namespace_and_set_cmd(self):
        self.log.info("Fetching namespace and setting kube_cmd")
        try:
            global pod_namespace
            global kube_cmd
            fetch_namespace = "env | grep POD_NAMESPACE | cut -d'=' -f2"
            pod_namespace = subprocess.check_output([fetch_namespace], shell=True).strip().decode()
            kube_cmd = "kubectl --kubeconfig={} -n {}".format(self.loc_admin_conf, pod_namespace)
            self.log.debug("Current Namespace is {} ".format(pod_namespace))
        except Exception as ex:
            print("Exception in fetching namespace")
            self.log.error("Exception in fetching namespace:: {}".format(ex))
            self.delete_ini_file()
            exit(1)
    # Fetch the name of service-0 pod. Needed for HA/Non-HA deployments.
    def get_service_0_pod_name(self):
        self.log.info("Fetching the name of service-0 pod")
        try:
            global pod_names
            global service_0_pod
            pod_name_cmd = "{} get pod -l app=eric-vnflcm-service | awk 'FNR >= 2 {{print $1}}'".format(kube_cmd)
            pod_names = subprocess.check_output([pod_name_cmd], shell=True).strip().decode().splitlines()
            self.log.info("List of service pods :: {}".format(pod_names))
            if not pod_names:
                self.log.error("Could not fetch service-0 pod name. Got null/empty")
                raise Exception("Could not fetch service-0 pod name. Got null/empty")
            else:
                service_0_pod = pod_names[0]
                self.log.info("Name of service-0 pod is found:: {}. Proceeding with the execution of script".format(service_0_pod))
        except Exception as ex:
            print("Exception in fetching servie-0 pod name")
            self.log.error("Exception in fetching servie-0 pod name:: {}".format(ex))
            self.delete_ini_file()
            exit(1)

    # NOT in use currently. Keeping the code for possibe future requirement.
    # retart replicas other than svc-0. To deploy war, update host entries etc
    def restart_service_pod_replicas(self):
        try:
            if len(pod_names) < 2:
                self.log.info("Only one eric-vnflcm-service instance present. Pod restart not required")
            else:
                i = 1
                while i < len(pod_names):
                    del_cmd = "{} delete pod {}".format(kube_cmd, pod_names[i])
                    self.log.info("Deleting the pod: {}".format(pod_names[i]))
                    del_result = subprocess.check_output([del_cmd], shell=True).strip().decode()
                    i += 1
        except Exception as ex:
            self.log.error("Error while restarting eric-vnflcm-service replicas:: {}".format(ex))
            print("Error in restarting eric-vnflcm-service replicas. Please perform rollout restart of the sts manually.")




    # Fetch the Idam hostname of eric-sec-access-mgmt for user authentication.
    def get_idam_host(self):
        self.log.info("Fetching idam hostname for user authentication")
        try:
            json_path = "-o jsonpath='{.spec.rules[*].host}'"
            ingress_cmd = "kubectl --kubeconfig={} get ingress -n {} | grep iam-ingress | awk '{}' | tail -1".format(self.loc_admin_conf, pod_namespace, "{print $1}")
            self.log.info("Ingress command prepared:: {}".format(ingress_cmd))
            hostname = subprocess.Popen([ingress_cmd], shell=True, stdout=subprocess.PIPE)
            result = hostname.communicate()[0].strip().decode()
            ing_name = result
            idam_hostname_cmd = ("{} get ingress {} {}").format(kube_cmd, ing_name, json_path)
            self.log.info("Idam hostname cmd :: {}".format(idam_hostname_cmd))
            self.idam_hostname = subprocess.check_output([idam_hostname_cmd], shell=True).strip().decode()
            self.log.debug("Idam hostname is {} ".format(self.idam_hostname))
        except Exception as ex:
            print("Exception in getting idam hostname ")
            self.log.error("Exception in getting idam hostname ")
            self.delete_ini_file()
            exit(1)

    # Pre-check for log file. Not required as it is going to be in docker image.
    def pre_requisite_file(self):

        try:
            if not os.path.exists(constants.log_path):
                os.mkdir(constants.log_path)
            if not os.path.exists(constants.log_file_path):
                open(constants.log_file_path, 'w').close()
        except:
            print("Exception in creating log file or directory")
            self.log.error("Exception in creating log file or directory")
            self.delete_ini_file()
            exit(1)

    # Find the vnflcm db master, since it's HA.
    def find_master_db(self):

        try:
            global master_db
            self.log.info("Checking for the master db")
            master_db_cmd = "{} get pods -L role | grep eric-vnflcm-db | grep  master | cut -d ' ' -f1".format(kube_cmd)
            master_db = subprocess.check_output([master_db_cmd], shell=True).strip().decode()
            self.log.info("Master db is found. Proceeding with the execution of script")
            return master_db
        except Exception as ex:
            print("Exception in finding master db")
            self.log.error("Exception in finding master db:: {}".format(ex))
            self.delete_ini_file()
            exit(1)

    def user_authentication(self):

        try:
            self.log.info("Evaluating the user credentials")
            data = {'username': self.evnfm_super_user_name, 'password': self.evnfm_super_user_password,
                    'grant_type': self.grant_type, 'client_id': self.client_id}
            evnfm_url = ("https://{}/auth/realms/master/protocol/openid-connect/token").format(self.idam_hostname)
            self.log.info("token url request {}".format(evnfm_url))
            token_response = requests.post(evnfm_url, data=data, verify=False)
            token_response.raise_for_status()
            token_response = token_response.json()
            access_token = token_response["access_token"]
            role_url = ("https://{}/auth/admin/realms/master/roles/{}").format(self.idam_hostname, self.role)
            headers = {'Content-type': 'application/json', 'Authorization': 'Bearer {}'.format(access_token)}
            get_role_response = requests.get(role_url, headers=headers, verify=False)
            response_status = get_role_response.status_code
            self.log.info("the response code is : {}".format(response_status))
            if response_status == 200:
                print(("The user {} is authorized proceeding with migration".format(self.evnfm_super_user_name)))
                self.log.info("USER {} is authorized proceeding with migration".format(self.evnfm_super_user_name))
                return True
            else:
                self.log.info("User {} is not authorized".format(self.evnfm_super_user_name))
                return False
        except requests.exceptions.ConnectionError as err:
            self.kill_polling_agent()
            print(("connection error", str(err)))
            self.delete_ini_file()
            exit(1)
        except requests.exceptions.HTTPError as err:
            self.kill_polling_agent()
            print(("unable to generate token of evnfm", str(err)))
            self.delete_ini_file()
            exit(1)
        except:
            print("user is not authorized")
            self.log.error("user is not authorized {} ".format(self.evnfm_super_user_name))
            self.delete_ini_file()
            exit(1)

    def exec_polling_agent(self):

        try:
            self.log.info("Proceeding with execution of Polling Agent")
            running_pollingAgent = ("python3 {} {} {} {} &").format(constants.pollingagent, self.loc_admin_conf,
                                                                pod_namespace, service_0_pod)
            os.system(running_pollingAgent)
        except:
            print("Error in execution of polling agent script")
            self.log.error("Error in execution of polling agent script")
            self.delete_ini_file()
            exit(1)

    def execution_in_pod(self):

        try:
            master_db = self.find_master_db()
            #local_to_svc_pod = ("{} cp {} {}:/tmp >/dev/null 2>&1").format(kube_cmd,
            #                                                                                  constants.restore_service, service_0_pod)
            #cp_local_to_svc_pod = os.system(local_to_svc_pod)
            #if cp_local_to_svc_pod == 0:
            #    self.log.info("service restore file is copied successfully")
            #else:
            #    self.log.error("Error in service restore file is copy")
            copy_camunda_uplift_script_cmd = "{} cp {} /eric-vnflcm-db-0:/tmp/camunda_uplift_script.sql".format(kube_cmd, constants.camunda_uplift_script)
            os.system(copy_camunda_uplift_script_cmd)
            copy_vnflafdb_upgrade_script_cmd = "{} cp {} /eric-vnflcm-db-0:/tmp/vnflafdb_upgrade_script.sql".format(kube_cmd, constants.vnflafdb_upgrade_script)
            os.system(copy_vnflafdb_upgrade_script_cmd)
            copy_wfs_upgrade_script_cmd = "{} cp {} /eric-vnflcm-db-0:/tmp/wfsdb_upgrade_script.sql".format(kube_cmd, constants.wfsdb_upgrade_script)
            os.system(copy_wfs_upgrade_script_cmd)
            print("scripts copied to db successfully")
            local_to_db_pod = ("tar cf - -P -C {} {} | {} exec -i {} -- tar xf - -C /tmp >/dev/null 2>&1").format(
                constants.main_dir, constants.restore_db, kube_cmd, master_db)
            cp_local_to_db_pod = os.system(local_to_db_pod)
            if cp_local_to_db_pod == 0:
                self.log.info("Db restore file is copied successfully")
            else:
                self.log.info("Error in db restore file is copy")
            with open(constants.state_file) as file:
                data = json.load(file)
            status_db = data["db_restore"]
            status_svc = data["svc_restore"]
            status_nfvo_update = data["nfvo_update"]
            status_health_check = data["health_check"]
            while status_db != "Success" or status_svc != "Success":
                svc_restore_cmd = "{} exec {} -c eric-vnflcm-service --  [ -f /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/bin/restoreservice.py ] >/dev/null 2>&1".format(
                    kube_cmd, service_0_pod)
                master_db = self.find_master_db()
                db_restore_cmd = '{} exec {} -c eric-vnflcm-db --  [ -f /tmp{} ] >/dev/null 2>&1'.format(kube_cmd,
                                                                                                         master_db,
                                                                                                         constants.restore_db)
                svc_restore_exists = os.system(svc_restore_cmd)
                db_restore_exists = os.system(db_restore_cmd)
                if [svc_restore_exists == 0] and [db_restore_exists == 0]:
                    self.log.info("Restore file is  present in respective pods")
                    with open(constants.state_file) as file:
                        data = json.load(file)
                    status_db = data["db_restore"]
                    status_svc = data["svc_restore"]
                    if status_db == "":
                        self.log.info("Proceeding with db restore")
                        master_db = self.find_master_db()
                        exec_db_restore = '{} exec {} -c eric-vnflcm-db -- python3 /tmp{} {} >> {}'.format(
                            kube_cmd, master_db, constants.restore_db, self.db_backup_tar_location,
                            constants.log_file_path)
                        os.system(exec_db_restore)
                        data["db_restore"] = "initializing"
                        self.log.info("db restore status is updated to initializing")
                        with open(constants.state_file, 'w') as json_file:
                            json.dump(data, json_file)
                        time.sleep(20)
                    elif status_db == "Success":
                        print("db restore successful")
                        self.log.info("db restore successful")
                        if status_svc == "":
                            self.log.info("Proceeding with service restore. Refer /var/log/vnflcm-admin-cli/logfile.log in services pod")
                            print("Proceeding with service restore")
                            exec_svc_restore = (
                                '{} exec {} -c eric-vnflcm-service -- sudo -E python3 /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/bin/restoreservice.py {} >> {}').format(
                                kube_cmd, service_0_pod, self.services_backup_tar_location, constants.log_file_path)
                            os.system(exec_svc_restore)
                            data["svc_restore"] = "initializing"
                            self.log.info("service restore status is updated to initializing")
                            with open(constants.state_file, 'w') as json_file:
                                json.dump(data, json_file)
                        elif status_svc == "Success":
                            print("svc restore successful")
                            self.log.info("svc restore successful")
                            self.check_for_non_encrypted_data()
                        elif status_svc != "Failed":
                            print(("svc restore script is ", status_svc))
                            self.log.info("svc restore script is {} ".format(status_svc))
                        elif status_svc == "Failed":
                            print("svc restore script failed")
                            self.log.error("svc restore script failed")
                            data_param = "svc_restore"
                            to_rerun = self.exec_script_again(data, data_param)
                            if to_rerun != True:
                                break
                    elif status_db != "Failed":
                        print(("db restore script is  " + status_db))
                        self.log.info("db restore script is {}  ".format(status_db))
                    elif status_db == "Failed":
                        print("db restore script failed")
                        self.log.error("db restore script failed")
                        data_param = "db_restore"
                        to_rerun = self.exec_script_again(data, data_param)
                        if to_rerun != True:
                            break
                else:
                    self.log.error("Restore file is not present in respective pods")
            if status_svc == "Success" and status_db == "Success":
                if self.enm_host != "" and self.enm_admin_user != "" and self.enm_admin_user_passwd != "" :
                    self.log.info("Both svc restore and db restore is successful. Proceeding with ENM User's migration")
                    self.execute_retriveusers()
                else:
                      self.log.info("Both svc restore and db restore is successful. Proceeding with NFVO update without ENM integration")
                self.log.info("Both svc restore and db restore is successful. Proceeding with NFVO update")
                if self.is_nfvo.lower() == "true":
                    self.eo_host = parser.get('MigrationInput', 'EO_Host')
                    self.eo_user_passwd = parser.get('MigrationInput', 'EO_USER_Passwd')
                    self.eo_user = parser.get('MigrationInput', 'EO_User')
                    self.eo_admin_tenant = parser.get('MigrationInput', 'EO_ADMIN_Tenant')
                    while status_nfvo_update != "Success":
                        to_rerun = self.call_nfvo_update()
                        if to_rerun != True:
                            break
                    with open(constants.state_file) as file:
                        data = json.load(file)
                    status_nfvo_update = data["nfvo_update"]
                    if status_nfvo_update == "Success" or status_nfvo_update == "Success-NoUpdateRequired":
                        self.log.info("nfvo update is successful. Proceeding with health check script")
                        self.call_health_script()
                else:
                    data["nfvo_update"] = "Success-NoUpdateRequired"
                    with open(constants.state_file, 'w') as json_file:
                        json.dump(data, json_file)
                    self.call_health_script()
            self.kill_polling_agent()
            self.cleanup_data()
            #not restarting svc pods. Might be required in future.
            #self.log.info("Checking if eric-vnflcm-service replicas need to be restarted...")
            #self.restart_service_pod_replicas()
            self.log.info("Migration script execution done")
            print("Migration script execution done ")
        except:
            print("Error in execution of script")
            self.log.error("Error in execution of script")
            self.delete_ini_file()
            exit(1)

    def exec_script_again(self, data, data_param):

        try:
            print("Do you want to execute the script again? yes/no")
            option = input()
            self.log.info("Do you want to execute the script again? User choose {}".format(option))
            if option.lower() == "yes":
                self.log.info("Proceeding with the re-execution again from the failed stage {} ".format(data_param))
                data[data_param] = ""
                with open(constants.state_file, 'w') as json_file:
                    json.dump(data, json_file)
                migration = Migration(file_path)
                return True
            else:
                print("exiting the script execution")
                self.log.error("Exiting the script")
                #self.delete_ini_file()
                return False
        except:
            self.kill_polling_agent()
            print("Exception in running the script again")
            self.log.error("Exception in running the script again")
            self.delete_ini_file()
            exit(1)

    def call_nfvo_update(self):
        try:
            self.log.info("Proceeding with nfvo update")
            with open(constants.state_file) as f:
                data = json.load(f)
            status_nfvo_update = data["nfvo_update"]
            data_param = "nfvo_update"
            status_health_check = data["health_check"]
            if status_nfvo_update == "":
                cp_nfvoupdate_cmd = ("{} cp {} {}:/tmp >/dev/null 2>&1").format(kube_cmd,
                                                                                                   constants.nfvo_and_vnfm_update, service_0_pod)
                os.system(cp_nfvoupdate_cmd)
                if self.eo_admin_tenant == "":
                    self.eo_admin_tenant = "dummy"
                args = '{} {} {} {} {} {} {}'.format(self.eo_host, self.eo_user, self.eo_user_passwd, self.evnfm_host,
                                                     self.evnfm_super_user_name, self.evnfm_super_user_password,
                                                     self.eo_admin_tenant)
                self.log.info("Executing nfvo update. Refer /var/log/vnflcm-admin-cli/logfile.log in services pod")
                exec_nfvo_update = (
                    "{} exec {} -c eric-vnflcm-service -- python3 /tmp/nfvoupdate.py {}").format(
                    kube_cmd, service_0_pod, args)
                os.system(exec_nfvo_update)
                time.sleep(20)
            elif status_nfvo_update == "Success":
                print("Nfvo Update is Successful")
                self.log.info("Nfvo Update is Successful")
                self.call_health_script()
            elif status_nfvo_update == "Failed":
                print("Nfvo Update failed")
                self.log.info("Nfvo Update failed")
                to_rerun = self.exec_script_again(data, data_param)
                return to_rerun
        except:
            self.kill_polling_agent()
            print("Exception in nfvo update")
            self.log.error("Exception in nfvo update")
            self.delete_ini_file()
            exit(1)

    # Need to find a new solution for executing health check from outside the services pod.
    def call_health_script(self):

        try:
            self.log.info("Proceeding with healthcheck script")
            with open(constants.state_file) as file:
                data = json.load(file)
            data_param = "health_check"
            cp_healthcheck_cmd = ("{} cp {} {}:/tmp >/dev/null 2>&1").format(kube_cmd,
                                                                                                constants.vmvnfm_health_check, service_0_pod)
            os.system(cp_healthcheck_cmd)
            self.log.info("Executing healthcheck. Refer /var/log/vnflcm-admin-cli/logfile.log in services pod")
            exec_health_check = (
                "{} exec {} -c eric-vnflcm-service -- python3 /tmp/healthCheckScript.py ").format(
                kube_cmd, service_0_pod)
            vnf_details = os.system(exec_health_check)
            if vnf_details == None:
                print("VNF's data is not available")
                self.log.info("VNF's data is not available")
            elif vnf_details != None:
                data["health_check"] = "Success"
                self.log.info("Health Check successful")
                with open(constants.state_file, 'w') as json_file:
                    json.dump(data, json_file)
        except:
            self.kill_polling_agent()
            print("Exception in executing health check script")
            self.delete_ini_file()
            exit(1)

    def check_for_running_process(self):

        try:
            self.log.info("Checking for running processes")
            response = self.user_authentication()
            if response:
                len_pid_other_script = self.running_pid_count("*")
                self.log.info("length of other scripts before killing the processses")
                self.log.info(len_pid_other_script)
                len_pid_polling_script = self.running_pid_count("*pollingagent")
                self.log.info("length of polling script before killing the processses")
                self.log.info(len_pid_polling_script)
                if len_pid_other_script > 2:
                    mig_process_id = str(os.getpid())
                    self.log.info("This is migration process ID :")
                    self.log.info(mig_process_id)
                    command_to_execute = "ps auxw | grep [p]ython | awk '{print $2}' | grep -v " + mig_process_id + " | xargs kill -9"
                    self.log.info(command_to_execute)
                    os.system(command_to_execute)
                    self.log.info("Killed all the user created processes")
                self.exec_polling_agent()
                self.log.info("Starting polling agent")
                len_pid_other_script = self.running_pid_count("*")
                self.log.info("this is length of other script after killing the user processes")
                self.log.info(len_pid_other_script)
                len_pid_polling_script = self.running_pid_count("*pollingagent")
                self.log.info("this is length of polling script after killing the user processes")
                self.log.info(len_pid_polling_script)
                if len_pid_other_script == 2 and len_pid_polling_script != 0:
                    print("No process is being executed ready to restore")
                    self.log.info("No process is being executed ready to restore")
                    self.execution_in_pod()
                else:
                    print("script being executed or Polling Agent script stopped executing")
                    self.delete_ini_file()
                    exit(1)
            else:
                self.log.error("user is not authorized")
                print("user is not authorized")
                self.delete_ini_file()
                exit(1)
        except:
            self.kill_polling_agent()
            print("Exception in checking for running process")
            self.log.error("Exception in checking for running process")
            self.delete_ini_file()
            exit(1)

    def running_pid_count(self, script):
        try:
            script_check = ("pgrep -f .*python3.{}.py").format(script)
            execution_script = [("pgrep -f .*python.{}.py").format(script)]
            process = subprocess.Popen(execution_script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            my_pid, err = process.communicate()
            self.log.info("Checking if any other script is already running")
            return len(my_pid.splitlines())
        except:
            print("Error in checking if any other script is being executed")
            self.log.error("Error in checking if any other script is being executed")
            self.delete_ini_file()
            exit(1)

    def kill_polling_agent(self):

        try:
            self.log.info("Post Migration , Proceeding with killing of Polling Agent")
            pid = "ps -ef | grep pollingagent.py | tr -s ' ' | cut -d ' ' -f2 |awk 'FNR <= 1'"
            PollingAgent_pid = subprocess.check_output([pid], shell=True)
            PollingAgent_pid = PollingAgent_pid.strip()
            pid_actual = int(PollingAgent_pid)
            os.system("kill -9 {}".format(pid_actual))
            self.log.debug("Post Migration ,Proceeding with killing of Polling Agent")
        except:
            print("Error in killing polling_agent script, kill the polling agent manually")
            self.log.error("Error in killing polling_agent script, kill the polling agent manually")
            self.delete_ini_file()
            exit(1)

    def cleanup_data(self):

        try:
            self.log.info("Proceeding with data cleanup")
            svc_cleanup_cmd = '{} exec {} -c eric-vnflcm-service --  rm -rf {} {} {} {}'.format(
                kube_cmd, service_0_pod, "/tmp/nfvoupdate.py", "/tmp/healthCheckScript.py",
                self.services_backup_tar_location, "/vnflcm-ext/.restoreVnflcmService.txt")
            db_cleanup_cmd = '{} exec {} -c eric-vnflcm-db --  rm -rf /tmp{} {} {}'.format(kube_cmd, master_db,
                                                                                           constants.restore_db,
                                                                                           self.db_backup_tar_location,
                                                                                           "/tmp/.restoreVnflcmDb.txt")
            svc_cleanup = os.system(svc_cleanup_cmd)
            if svc_cleanup == 0:
                self.log.info("cleanup successful in service pod")
                print("backup data of service and restore status file has been cleaned in service pod")
            db_cleanup = os.system(db_cleanup_cmd)
            if db_cleanup == 0:
                self.log.info("cleanup successful in db pod")
                print("backup data of db and restore status file in db has been cleaned in DB pod")
            #check for config params un-encrypted
            # self.check_for_non_encrypted_data()
            # Deleting the sample ini file to protect passwords.
            self.execute_delete_ini_cmd()
        except:
            print("Unable to cleanup the scripts and Tar files. Cleanup manually")
            self.log.error("Unable to cleanup the scripts and Tar files. Cleanup manually")
            self.delete_ini_file()
            exit(1)

# This is added temorarily since print from restoreservice.py is not outputting in terminal
    def check_for_non_encrypted_data(self):
        check_params_not_encrypted = (
                '{} exec {} -c eric-vnflcm-service -- bash -c " [ -f /var/tmp/.non_encrypted.txt ] && cat /var/tmp/.non_encrypted.txt" > /var/tmp/.non_encrypted.txt').format(
                kube_cmd, service_0_pod)
        os.system(check_params_not_encrypted)
        missedParams = []
        with open(r'/var/tmp/.non_encrypted.txt', 'r') as fp:
            for line in fp:
                x = line[:-1]
                missedParams.append(x)
        if not missedParams:
            print("All  sensive pconfiguration aramters are encrypted successfully")
        else:
            print('Following parameters could not be encrypted, or are empty: {}.\n Please encrypt these manually'.format(missedParams))
        os.system('rm -f /var/tmp/.non_encrypted.txt')
        del_list_in_svc = (
                    '{} exec {} -c eric-vnflcm-service -- rm -f /var/tmp/.non_encrypted.txt').format(
                    kube_cmd, service_0_pod)
        os.system(del_list_in_svc)

    def execute_retriveusers(self):

        try:
            exec_retrive_users = "python {} {} {} {} {} {} {} {}".format(constants.retriveusers, self.enm_host,
                                                                         self.enm_admin_user,
                                                                         self.enm_admin_user_passwd, self.idam_hostname,
                                                                         self.evnfm_user_name, self.evnfm_user_password,
                                                                         self.client_id)
            exec_script = subprocess.call([exec_retrive_users], shell=True)
            print("addition or retrieval of user successful")
            self.log.info("addition or retrieval of user successful")
        except:
            print("Unable to add or retrieve users, Add users manually")
            self.log.error("Unable to add or retrieve users, Add users manually")
            self.delete_ini_file()
            exit(1)

    def service_backup_file_check(self):
        try:
            with open(constants.state_file) as file:
                data = json.load(file)
            if data['svc_restore'] != 'Success':
                print('Checking eric-vnflcm-service backups')
                service_backup_path = '{} exec {} -c eric-vnflcm-service -- find {}'.format(kube_cmd, service_0_pod, str(self.services_backup_tar_location).split('mig_data')[0])
                svc_output =  subprocess.check_output([service_backup_path], shell=True).decode()
                if self.services_backup_tar_location in str(svc_output):
                    ispresent = True
                    if '{}/config'.format(self.services_backup_tar_location) not in str(svc_output):
                        print(('config backup not present at {}'.format(self.services_backup_tar_location)))
                        self.log.error('config backup not present at {}'.format(self.services_backup_tar_location))
                        ispresent = False
                    if '{}/jboss_logs'.format(self.services_backup_tar_location) not in str(svc_output):
                        print(('jboss_logs backup not present at {}'.format(self.services_backup_tar_location)))
                        self.log.error('jboss_logs backup not present at {}'.format(self.services_backup_tar_location))
                        ispresent = False
                    if not ispresent:
                        print('Exiting Migration as backup is not present')
                        self.log.error('Exiting Migration as backup is not present')
                        self.delete_ini_file()
                        exit(1)
                    else:
                        print('Backup present for service restore. Proceeding further')
                        self.log.info('Backup present for service restore. Proceeding further')
                else:
                    print(('mig_data directory not present at location {}. Hence Exiting Migration.'.format(self.services_backup_tar_location)))
                    self.log.error('mig_data directory not present at location {}. Hence Exiting Migration.'.format(self.services_backup_tar_location))
                    self.delete_ini_file()
                    exit(1)
        except Exception as e:
            print(('Exception raised while checking service backup',str(e)))
            self.log.error('Exception raised while checking service backup',str(e))
            self.delete_ini_file()
            exit(1)

    def db_backup_file_check(self):
        try:
            with open(constants.state_file) as file:
                data = json.load(file)
            if data['db_restore'] != 'Success':
                print('Checking eric-vnflcm-db backups')
                master_db = self.find_master_db()
                db_backup_path = '{} exec {} -c eric-vnflcm-db -- find {}'.format(kube_cmd, master_db, str(self.db_backup_tar_location).split('mig_data')[0])
                db_output =  subprocess.check_output([db_backup_path], shell=True).decode()
                if self.db_backup_tar_location in str(db_output):
                    if '{}/'.format(self.db_backup_tar_location) not in str(db_output):
                        print(('db backup not present at {}'.format(self.db_backup_tar_location)))
                        self.log.error('db backup not present at {}'.format(self.db_backup_tar_location))
                        print('Exiting Migration as backup is not present')
                        self.log.error('Exiting Migration as backup is not present')
                        self.delete_ini_file()
                        exit(1)
                    else:
                        print('Backup present for db restore. Proceeding further')
                        self.log.info('Backup present for db restore. Proceeding further')
                else:
                    print(('mig_data directory not present at location {}. Hence Exiting Migration.'.format(self.db_backup_tar_location)))
                    self.log.error('mig_data directory not present at location {}. Hence Exiting Migration.'.format(self.db_backup_tar_location))
                    self.delete_ini_file()
                    exit(1)
        except Exception as e:
            print(('Exception raised while checking db backup',str(e)))
            self.log.error('Exception raised while checking db backup',str(e))
            self.delete_ini_file()
            exit(1)

    def state_file_check(self):
        try:
            with open(constants.state_file) as file:
                data = json.load(file)
            if (list(data.values()).count('Success') + list(data.values()).count('Success-NoUpdateRequired')) == 4:
                print(('State file contents are - {}'.format(str(data).replace("u'", "'"))))
                while True:
                    reset_input = input('For new Migration, Do you want to reset all the values of state_file.json to ""? [y/N]')
                    if str(reset_input).lower() == 'y':
                        data["db_restore"] = ""
                        data["svc_restore"] = ""
                        data["nfvo_update"] = ""
                        break
                    elif str(reset_input).lower() == 'n':
                        break
            else:
                for state in list(data.keys())[::-1]:
                    if data[state] == "Failed" and state != "health_check":
                        print(('State file contents are - {}'.format(str(data).replace("u'", "'"))))
                        while True:
                            reset_input = input('To continue with Migration, Do you want to reset the value of {} in state_file.json to ""? [y/N]'.format(state))
                            if str(reset_input).lower() == 'y':
                                data[state] = ""
                                break
                            elif str(reset_input).lower() == 'n':
                                break
            data["health_check"] = ""
            with open(constants.state_file, 'w') as json_file:
                json.dump(data, json_file)
            with open(constants.state_file) as file:
                data = json.load(file)
            print(('State file contents are - {}'.format(str(data).replace("u'", "'"))))
        except:
            print('Exception raised while checking state file')

    def delete_ini_file(self):
        try:
            print("Do you want to delete the migration input file? yes/no")
            del_option = input()
            self.log.info("Do you want to delete the migration input file? User choose {}".format(del_option))
            if del_option.lower() == "yes":
                self.execute_delete_ini_cmd()
            elif del_option.lower() != "no":
                print('Invalid user input provided: input file will not be deleted. Please Delete the file manually')
        except:
            print('Unable to delete the input file. Please delete it manually.')
    
    def execute_delete_ini_cmd(self):
        try:
            print("Deleting the migration input file.")
            del_cmd = 'rm -f ' + str(file_path)
            cmd_exit_code = os.system(del_cmd + "&> /dev/null")
            if cmd_exit_code == 0:
                self.log.info('migration ini file deleted successfully')
            else:
                print('Unable to delete the input file. Please delete it manually.')
        except:
            print('Unable to delete the input file. Please delete it manually.')


def main():
    try:
        if len(sys.argv) == 2:
            migrationInput_file = sys.argv[1]
            global file_path
            file_path = os.path.realpath(migrationInput_file)
            if migrationInput_file is not None:
                migration = Migration(file_path)
                migration.validation_of_user_input_file()
                migration.pre_requisite_file()
                migration.get_namespace_and_set_cmd()
                migration.get_idam_host()
                migration.find_master_db()
                migration.get_service_0_pod_name()
                migration.state_file_check()
                migration.db_backup_file_check()
                migration.service_backup_file_check()
                # migration.exec_polling_agent()
                migration.check_for_running_process()
        else:
            print("Please provide the input file as argument, Check whether migration.ini file is present or not")
            exit(1)
    except:
        print("Exception occurred while running migration script")
        exit(1)


if __name__ == '__main__':
    main()
