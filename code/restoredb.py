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
import time
import datetime


class RestoreDb:

    def __init__(self):
        self.class_name = "[RestoreDb]"
        self.final_backup_dir = sys.argv[1]
        self.status = ""
        self.output_file = "/tmp/.restoreVnflcmDb.txt"
        self.pg_user = "postgres"
        self.pg_root = "/opt/rh/rh-postgresql94/root/usr/bin"
        self.vnflaf_database = "vnflafdb"
        self.sfwk_database = "sfwkdb"
        self.wfs_database = "wfsdb"

    def create_final_backup_dir(self, args):
        print((self.class_name + " - Creating final backup directory"))
        self.status = "create_final_backup_dir():Processing"
        with open(self.output_file, 'w') as state_file:
            state_file.write(self.status + '\n')
            if len(args) == 2:
                if not os.path.isdir(self.final_backup_dir):
                    self.status = "create_final_backup_dir():Failed"
                    state_file.write(self.status + '\n')
                    print((self.class_name + " - Directory " + self.final_backup_dir + "doesn't exist ..exiting backup"))
                    exit(1)
                else:
                    self.check_if_secure_params_supported()
                    self.perform_restore(state_file)
                    print((self.class_name + " - restore is done, now checking db "))
                    time.sleep(5)
                    self.check_db_status()
            else:
                print((self.class_name + " - The number of arguments must be equal to 2"))
                self.status = "create_final_backup_dir():Failed"
                state_file.write(self.status + '\n')
                exit(1)
    def check_if_secure_params_supported(self):
        try:

            cmd = "psql -t -U postgres -d sfwkdb -c \"select single_value from configuration_parameter where name='isSecureSensitiveParamsSupported';\"| xargs > /tmp/.isSecureSensitiveParamsSupported"
            result = os.system(cmd)
            if result != 0 :
                print("Value of isSecureSensitiveParamsSupported could not be cecked before migration.Default value will be used.")
        except Exception:
            print("Exception in reading original value of isSecureSensitiveParamsSupported")

    def check_db_status(self):
        print((self.class_name + " - Checking db status"))
        result = ""
        try:
            cmd = "psql -U postgres -d wfsdb -c 'select root_proc_inst_id_ from act_ru_execution' /dev/null 2>&1"
            result = os.system(cmd)
            if result != 0 :
                print((self.class_name + " - Running scripts to make db post migration compatible"))
                script1_run = "psql -U postgres -d wfsdb -a -f /tmp/camunda_uplift_script.sql"
                os.system(script1_run)
        except:
            pass


    def extract_db_tar(self, db_type, restore_filename, state_file):
        self.status = "extract_db_tar():Processing"
        state_file.write(self.status + '\n')
        unzip_status = 1
        print((self.class_name + " - Restoring Plain backup of {} from file {}".format(db_type, restore_filename)))
        if not os.path.isfile(restore_filename):
            self.status = "extract_db_tar():Failed"
            state_file.write(self.status + '\n')
            print((self.class_name + " - Cannot restore backup file {} doesn't exist. Please provide the valid file name to "
                  "restore the DB.".format(restore_filename)))
            exit(1)
        else:
            unzip_status = os.system('cat {} | gunzip | psql -U {} --d {} > /dev/null  2>&1'
                                     .format(restore_filename, self.pg_user, db_type))
        return unzip_status

    def perform_restore(self, state_file):
        print((self.class_name + " - Performing db restore"))
        self.status = "perform_restore():Processing"
        state_file.write(self.status + '\n')
        vnflafdb_restore_output = self.extract_db_tar(self.vnflaf_database, '{}/{}.sql.gz'
                                                  .format(self.final_backup_dir, self.vnflaf_database), state_file)
        if vnflafdb_restore_output == 0:
            script2_run = "psql -U postgres -d vnflafdb -a -f /tmp/vnflafdb_upgrade_script.sql"
            os.system(script2_run)
            print((self.class_name + " - Restoration of {} completed".format(self.vnflaf_database)))

            sfwkdb_restore_output = self.extract_db_tar(self.sfwk_database, '{}/{}.sql.gz'
                                                    .format(self.final_backup_dir, self.sfwk_database), state_file)
            if sfwkdb_restore_output == 0:
                print((self.class_name + " - Restoration of {} completed".format(self.sfwk_database)))

                wfsdb_restore_output = self.extract_db_tar(self.wfs_database, '{}/{}.sql.gz'
                                                       .format(self.final_backup_dir, self.wfs_database), state_file)
                if wfsdb_restore_output == 0:
                    script3_run = "psql -U postgres -d wfsdb -a -f /tmp/wfsdb_upgrade_script.sql"
                    #wfsdb_upgrade_script.sql needs to be updated when required and
                    #the below cmd needs to be executed when there is any wfsdb schema change
                    os.system(script3_run)
                    print((self.class_name + " - Restoration of {} completed".format(self.wfs_database)))
                    self.db_restore_complete(state_file)
                else:
                    print((self.class_name + " - Restoration of {} failed".format(self.wfs_database)))
                    self.status = "perform_restore():Failed"
                    state_file.write(self.status + '\n')
                    exit(1)
            else:
                print((self.class_name + " - Restoration of {} failed".format(self.sfwk_database)))
                self.status = "perform_restore():Failed"
                state_file.write(self.status + '\n')
                exit(1)
        else:
            print((self.class_name + " - Restoration of {} failed".format(self.vnflaf_database)))
            self.status = "perform_restore():Failed"
            state_file.write(self.status + '\n')
            exit(1)

    def restore_encryption_status(self):
        try:
            status = "false"
            with open(r'/tmp/.isSecureSensitiveParamsSupported', 'r') as fp:
                for line in fp:
                    status = line.strip()
            now = datetime.datetime.utcnow()
            cmd = "psql -U postgres -d sfwkdb -c \"insert into configuration_parameter (id, description, last_modification_time, name, property_scope, status, type_as_string, single_value) values ('GLOBAL___isSecureSensitiveParamsSupported', 'Config param isSecureSensitiveParamsSupported', {}, 'isSecureSensitiveParamsSupported', 'GLOBAL', 'CREATED_NOT_MODIFIED', 'java.lang.String', '{}');\"".format(int(round(now.timestamp())) ,status)
            result = os.system(cmd)
            if result != 0:
                print("isSecureSensitiveParamsSupported value could not be restored.")
            rm_cmd = "rm -f /tmp/.isSecureSensitiveParamsSupported"
            os.system(rm_cmd)
        except Exception:
            print("Exception while restoring value of isSecureSensitiveParamsSupported")

    def db_restore_complete(self, state_file):
        self.restore_encryption_status()
        self.status = "db_restore:Success"
        state_file.write(self.status + '\n')
        print((self.class_name + " - DB is restored successfully."))

    def main(self):
        self.create_final_backup_dir(sys.argv)


if __name__ == "__main__":
    restore_db = RestoreDb()
    restore_db.main()
