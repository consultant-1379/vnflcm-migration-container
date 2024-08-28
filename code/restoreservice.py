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

import os
import sys
import subprocess
import requests
import socket

sys.path.insert(1, '/opt/ericsson/ERICvnflcmadmincli_CXP9033981/')
from common.vnflcmlog import VnfLcmLog


class RestoreService:

    def __init__(self):
        self.log = VnfLcmLog("RestoreService[Migration]")
        self.final_backup_dir = sys.argv[1]
        self.status = ""
        self.output_file = "/vnflcm-ext/.restoreVnflcmService.txt"
        self.vnf_backup_config = "config"
        self.vnf_backup_jboss_logs = "jboss_logs"
        self.rm = "/usr/bin/rm"
        self.vnflaf_persist_storage_path = "/vnflcm-ext/"
        self.instances_path = "/vnflcm-ext/current/vnf_instances"
        self.vnfAuthorizedKeys_path = "/vnflcm-ext/current/vnf_access_authorized_keys"
        self.tar = "/usr/bin/tar"
        self.autostart_orig_path = "/etc/opt/ericsson/ERICvnflafautostartservice_CXP9032572"
        self.autostart_bkp_path = "/vnflcm-ext/current/workflows/auto-start-rules"
        self.unlink = "/usr/bin/unlink"
        self.cacerts_orig_file = "/usr/java/default/jre/lib/security/cacerts"
        self.cacerts_bkp_file = "/vnflcm-ext/current/workflows/keystore-cacerts"

    # Perform_initial_checks - Performs initial checks before proceeding to restore
    def perform_initial_checks(self, args):
        self.log.info("Performing initial checks")
        self.status = "perform_initial_checks():Processing"
        with open(self.output_file, 'w') as state_file:
            state_file.write(self.status + '\n')

            if len(args) == 2:
                if not os.path.isdir(self.final_backup_dir):
                    self.status = "perform_initial_checks():Failed"
                    state_file.write(self.status + '\n')
                    self.log.info("Directory {} doesn't exist ..exiting backup".format(self.final_backup_dir))
                    print(("Directory " + self.final_backup_dir + "doesn't exist ..exiting backup"))
                    exit(1)
                else:
                    self.log.info("Directory {} exists, Proceeding with config restore".format(self.final_backup_dir))
                    self.perform_config_restore(state_file)
            else:
                self.log.error("The number of arguments must be equal to 2. Number of arguments is/are {}".format(len(args)))
                print(("The number of arguments must be equal to 2. Number of arguments is/are {}".format(len(args))))
                self.status = "perform_initial_checks():Failed"
                state_file.write(self.status + '\n')
                exit(1)

    # executes the shell command and returns the output
    def execute_shell(self, cmd):
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            return out.decode()
        except Exception as Err:
            self.log.exception("error in execution of command: %s" % str(Err), self)
            return ''
    # encrypt sensitive config params during migration
    def encrypt_config_params(self):
        try:
            self.log.info("Proceeding to encrypt sensitive config params")
            isPasswordProtectionEnabled = self.execute_shell("/usr/bin/python2 /ericsson/pib-scripts/etc/config.py read --app_server_address localhost:8080 --name=isSecureSensitiveParamsSupported")
            
            if isPasswordProtectionEnabled is not None and isPasswordProtectionEnabled:
                subprocess.call(['/usr/bin/sh', '/opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/bin/config.sh'])
                defaultList = list(self.execute_shell("/usr/bin/python2 /ericsson/pib-scripts/etc/config.py read --app_server_address localhost:8080 --name=sensitiveConfigParamsList").replace('\n','').split(','))
                dynamicList = list(self.execute_shell("/usr/bin/python2 /ericsson/pib-scripts/etc/config.py read --app_server_address localhost:8080 --name=encryptedConfigParamsList").replace('\n','').split(','))
                missedParams = []
                for i in defaultList:
                    if i not in dynamicList:
                        missedParams.append(i)
                if not missedParams:
                    self.log.info("All default sensive paramters are encrypted")
                else:
                    print('Following parameters could not be encrypted: {}.\n Please encrypt these manually'.format(missedParams))
                    self.log.error('All parameters could not be encrypted during migration. Encryption pending for: {}'.format(missedParams))
                    with open(r'/var/tmp/.non_encrypted.txt', 'w') as fp:
                        for item in missedParams:
                            fp.write("%s\n" % item)
    
        except:
            print("Something went wrong while encrypting sensitive configuration parameters. Please encrypt the values manually.")
            self.log.info("Something went wrong while encrypting sensitive configuration parameters. Please encrypt the values manually.")

    # Perform_config_restore - Performs restore of vnflafservice
    def perform_config_restore(self, state_file):
        self.log.info("Performing config restore")
        self.status = "perform_config_restore():Processing"
        state_file.write(self.status + '\n')
        backup_filename = self.final_backup_dir + "/" + self.vnf_backup_config \
                          + "/config.tar.gz," + self.final_backup_dir + "/" + \
                          self.vnf_backup_jboss_logs + "/jboss_logs.tar.gz"
        self.log.info("Backup filename is:: {}".format(backup_filename))
        self.log.info("Cleaning up destination directories before restore.")
        print("Cleaning up destination directories before restore.")
        os.system('find /vnflcm-ext/current/* -type d | egrep -v "logs|db" > /vnflcm-ext/output.txt')
        try:
            with open('/vnflcm-ext/output.txt', 'r') as f2:
                for path in f2.read().splitlines():
                    self.log.info("Cleaning up directory:: {}".format(path))
                    print(("Cleaning up directory {}".format(path)))
                    os.system("{} -rf {}".format(self.rm, path))
            self.log.info("Removing file /vnflcm-ext/output.txt")
            os.system('rm -rf /vnflcm-ext/output.txt')
        except IOError:
            self.log.error("Could not find file /vnflcm-ext/output.txt")
            print("Could not find file /vnflcm-ext/output.txt")
        os.chdir(self.vnflaf_persist_storage_path)
        for backup_file in backup_filename.split(','):
            self.log.info("Restoring files from backup file:: {}".format(backup_file))
            print(('Restoring files from backup file' + backup_file))
            if os.path.isfile(backup_file):
                self.log.info("Restoring from backup file {} , Decompressing it.".format(backup_file))
                print(('Restoring from backup file {} , Decompressing it.'.format(backup_file)))
            else:
                self.status = "perform_config_restore():Failed"
                state_file.write(self.status + '\n')
                self.log.info("Back up file {} doesn't exist.".format(backup_file))
                print(("Back up file {} doesn't exist.".format(backup_file)))
                exit(1)
            os.system("{} -pzxvf {} --exclude='vnflcm.versions' --exclude='.vnflcm.status' --exclude='.htpasswd' "
                      "--exclude='ssl-ca-bundle.crt' --exclude='/etc/hosts'".format(self.tar, backup_file))
            os.chdir('/')
            self.log.info("Proceeding with creating syslinks")
            self.create_syslinks(state_file)

    # create_syslinks - link auto-start and cacerts original path to backup path if it does not exit.
    def create_syslinks(self, state_file):
        self.log.info("Linking {} to {}".format(self.autostart_orig_path, self.autostart_bkp_path))
        print(("Linking {} to {}".format(self.autostart_orig_path, self.autostart_bkp_path)))
        self.status = "create_syslinks():Processing"
        state_file.write(self.status + '\n')
        if os.path.islink(self.autostart_orig_path):
            self.log.info("Path {} is a link".format(self.autostart_orig_path))
            os.system(self.unlink + ' ' + self.autostart_orig_path)
        if os.path.isdir(self.autostart_orig_path):
            self.log.info("Path {} is a directory".format(self.autostart_orig_path))
            os.system(self.rm + ' -rf ' + self.autostart_orig_path)
        os.system('ln -s ' + self.autostart_bkp_path + ' ' + self.autostart_orig_path)
        self.log.info("Linking {} to {}".format(self.cacerts_orig_file, self.cacerts_bkp_file))
        print(("Linking {} to {}".format(self.cacerts_orig_file, self.cacerts_bkp_file)))
        if os.path.islink(self.cacerts_orig_file):
            self.log.info("File {} is a link".format(self.cacerts_orig_file))
            os.system(self.unlink + ' ' + self.cacerts_orig_file)
        if os.path.isdir(self.cacerts_orig_file):
            self.log.info("File {} is a directory".format(self.cacerts_orig_file))
            os.system(self.rm + ' -rf ' + self.cacerts_orig_file)
        os.system('ln -s ' + self.cacerts_bkp_file + ' ' + self.cacerts_orig_file)
        self.log.info("Proceeding with configuring restore work directory")
        self.configure_restore_work_directory(state_file)

    # Restarting jboss.
    def restart_jboss(self):
        self.log.info("Restarting jboss")
        print("Restarting jboss")
        jboss_status = os.system("sudo jboss restart")
        if not jboss_status == 0:
            self.log.error("Jboss didn't start properly. So exiting.")
            print("Jboss didn't start properly. So exiting.")
            exit(1)

    def service_restore_complete(self, state_file):
        self.status = "Service_Restore:Success"
        state_file.write(self.status + '\n')
        self.log.info("Service is restored successfully")
        print('Service is restored successfully')

    def configure_restore_work_directory(self, state_file):
        self.log.info("Configuring restore work directory")
        self.status = "configure_restore_work_directory():Processing"
        state_file.write(self.status + '\n')
        restore_work_directory_status = os.system('source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/vnflcm_inst_utils.lib ; '
                                                  'source /ericsson/vnflcm/data/vnflcm.properties ; '
                                                  'source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/configure_restore.lib ; '
                                                  'source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/configure_params.lib ;update_config_params; '
                                                  'log_init /var/log/vnflcm/configure_restore.log ; log_debug ; '
                                                  'configure_restore_work_directory ; update_vnfconfigrepo_param ')
        if restore_work_directory_status == 0:
            self.log.info("Restoration of work directory successful, Proceeding with jboss restart")
            self.restart_jboss()
            if not os.path.exists(self.instances_path):
                self.log.info("Creating the vnf_instances directory")
                os.mkdir(self.instances_path)
            if not os.path.exists(self.vnfAuthorizedKeys_path):
                self.log.info("Creating the vnf_access_authorized_keys directory")
                os.mkdir(self.vnfAuthorizedKeys_path)
            self.log.info("Proceeding with configuring restore rpm")
            self.configure_restore_rpm(state_file)
        else:
            self.log.error("Restoration of work directory failed, restore work directory status is:: {}".format(restore_work_directory_status))
            print("Restoration of work directory failed.")
            self.status = "configure_restore_work_directory():Failed"
            state_file.write(self.status + '\n')
            exit(1)

    def set_permissions(self):
        self.log.info("Assigning the permissions and ownership")
        print("Assigning the permissionsand ownership")
        try:
            self.log.info("Setting permission")
            print("Setting permission")
            subprocess.call(['chmod', '-R', '0777', '/vnflcm-ext/'])
            self.log.info("Setting user and group")
            print("Setting user and group")
            subprocess.call(['chown', '-R', 'eric-vnflcm-service:eric-vnflcm-service', '/vnflcm-ext/'])
            print("Setting correct permissions and ownership for sh keys")
            subprocess.call(['/usr/bin/sh', '/opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/bin/alterKeyPermissions.sh'])
        except subprocess.CalledProcessError as Err:
            self.log.error("Error in execute command:: {}".format(str(Err)))
            print(("Error in execute command:: {}".format(str(Err))))

    def configure_restore_rpm(self, state_file):
        self.log.info("Configuring restore rpm")
        self.status = "configure_restore_rpm():Processing"
        state_file.write(self.status + '\n')
        restore_rpm_status = os.system('source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/vnflcm_inst_utils.lib ; '
                                       'source /ericsson/vnflcm/data/vnflcm.properties ; '
                                       'source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/configure_restore.lib ; '
                                       'log_init /var/log/vnflcm/configure_restore.log ; log_debug ; configure_restore_rpm')
        if restore_rpm_status == 0:
            self.log.info("Restoration of rpms successful, Proceeding with Installation of rpms")
            self.install_rpm(state_file)
        else:
            self.log.error("Restoration of rpms failed, restore rpm status is:: {}".format(restore_rpm_status))
            print("Restoration of rpms failed.")
            self.status = "configure_restore_rpm():Failed"
            state_file.write(self.status + '\n')
            exit(1)

    def install_rpm(self, state_file):
        self.log.info("Installing rpms")
        self.status = "install_rpm():Processing"
        state_file.write(self.status + '\n')
        install_rpm_status = os.system('source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/vnflcm_inst_utils.lib ; '
                                       'source /ericsson/vnflcm/data/vnflcm.properties ; '
                                       'source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/configure_restore.lib ; '
                                       'log_init /var/log/vnflcm/configure_restore.log ; log_debug ; install_cluster_worker_node ; install_discover_vnf')
        if install_rpm_status == 0:
            self.log.info("Installation of rpms successful, Proceeding with restoring cloud host entries")
            self.restore_cloud_host_entry(state_file)
            # restore host entries in other replica in case of HA
            replica_ip = self.get_Replica_Ip()
            self.log.info("Replica IP:" + replica_ip)
            if not replica_ip:
                self.log.info("Hosts updation in replica  not needed.")
            else:
                addr =  "http://" + replica_ip + ":5000/vnflcm-admin/v1/host-entries/restore"
                #Make post Call to the replica
                resp = requests.post(addr)
                if resp.status_code == 200:
                    self.log.info("Host entries restored in replica")
                else:
                    self.log.error("Error in restoring host entries in replica.")
                    print("Could not restore host file entries for eric-vnflcm-service replicas")
                    print("Please manually restart all service pod replicas to restore host entries.")
        else:
            self.log.error("Installation of rpms failed, install rpm status is:: {}".format(install_rpm_status))
            print("Installation of rpms failed.")
            self.status = "install_rpm():Failed"
            state_file.write(self.status + '\n')
            exit(1)

    def restore_cloud_host_entry(self, state_file):
        self.log.info("Restoring cloud host entries")
        self.status = "restore_cloud_host_entry():Processing"
        state_file.write(self.status + '\n')
        restore_cloud_host_entry_status = os.system('source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/vnflcm_inst_utils.lib ; '
                                                    'source /ericsson/vnflcm/data/vnflcm.properties ; '
                                                    'source /opt/ericsson/ERICvnflcmservicecontainer_CXP9037964/lib/configure_restore.lib ; '
                                                    'log_init /var/log/vnflcm/configure_restore.log ; log_debug ; '
                                                    'restore_cloud_host_entry ; apply_autoheal_fix')
        if restore_cloud_host_entry_status == 0:
            self.log.info("Restoration of cloud host entry successful.")
            self.set_permissions()
            self.encrypt_config_params()
            self.service_restore_complete(state_file)
        else:
            self.log.error("Restoration of cloud host entry failed, restore cloud host entry status is:: {}".format(restore_cloud_host_entry_status))
            print("Restoration of cloud host entry failed.")
            self.status = "restore_cloud_host_entry():Failed"
            state_file.write(self.status + '\n')
            exit(1)

    def get_Replica_Ip(self):
        try:
            is_ha_deployment = os.getenv('IS_HA_Deployment')
            if (is_ha_deployment == "True" or is_ha_deployment == "true"):
                NAMESPACE = os.getenv('NAMESPACE')
                self.log.info("NameSpace:"+NAMESPACE)
                addrInfo = socket.getaddrinfo("eric-vnflcm-service-headless." + NAMESPACE + ".svc.cluster.local", None)
                self.log.info(str(addrInfo))

                ip_address_current_replica = socket.gethostbyname(socket.gethostname())
                self.log.info("IP Address of VM VNFM current Replica: " + ip_address_current_replica)

                for address in addrInfo:
                    ip_address = address[-1][0]
                    if (ip_address != ip_address_current_replica):
                        self.log.info("IP Address of VM VNFM other Replica: " + ip_address)
                        return ip_address
            else:
                self.log.info("Not an HA deployment.")
                return ""

        except Exception as exc:
            self.log.exception("error in get_Replica_Ip %s" % str(exc), self)

    def main(self):
        self.perform_initial_checks(sys.argv)

if __name__ == "__main__":
    restoreService = RestoreService()
    restoreService.main()
