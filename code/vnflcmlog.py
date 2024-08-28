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

import configparser
import logging
import os
import subprocess
from logging.handlers import RotatingFileHandler
import constants


class VnfLcmLog:
    class __VnfLcmLog:
        pass

        def retrieve_config_val(self, filename):

            try:
                config_dict = {}
                config = configparser.RawConfigParser()
                config.read(filename)
                loglevel = config.get('PropertySection', 'log.level')
                if not loglevel:
                    print("Log level not defined in config.properties.Using default level as info")
                    config_dict["log_level"] = "INFO"
                else:
                    config_dict["log.level"] = loglevel
                return config_dict
            except:
                raise
                print("Exception while reading config property")

        def __init__(self, classname):
            try:
                basepath = os.path.dirname(__file__)
                config_file = os.path.abspath(os.path.join(basepath, "common.properties"))
                config_dict = self.retrieve_config_val(config_file)
                self.classname = classname
                self.logger = logging.getLogger(classname)
                filename_str = constants.log_path + "/" + "logfile.log"
                self.touch_logfile(filename_str)
                fh = logging.FileHandler(filename_str)

                rotation_handler = RotatingFileHandler(filename_str, maxBytes=100 * 1024 * 1024,
                                                       backupCount=5)

                self.logger.addHandler(rotation_handler)

                log_level = config_dict.get("log.level")
                level_lower = log_level.lower()
                if (level_lower == "debug"):
                    self.logger.setLevel(logging.DEBUG)
                    fh.setLevel(logging.DEBUG)

                elif (level_lower == "info"):
                    self.logger.setLevel(logging.INFO)
                    fh.setLevel(logging.INFO)

                formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                fh.setFormatter(formatter)
                self.logger.addHandler(fh)
            except:
                raise
                print("Error in waflog")

        def info(self, log_message, obj=None):
            self.logger.info(log_message)

        def debug(self, log_message, obj=None):
            self.logger.debug( log_message)

        def warning(self, obj, log_message):
            self.logger.warning(log_message)

        def critical(self, obj, log_message):
            self.logger.critical(log_message)

        def error(self, log_message, obj=None):
            self.logger.error(log_message)

        def exception(self, log_message, obj=None):
            self.logger.exception(log_message)

        def touch_logfile(self, file_name):
            cmd = "touch %s; chmod 777 %s > /dev/null 2>&1" % (file_name, file_name)

            # print "comand is " , cmd

            response = self.execute_command(cmd)
            # print "response of log file creation is " , response
            if (response == 0):
                return True
            else:
                return False

        def execute_command(self, cmd_str):
            try:
                # print "cmd is " , cmd_str
                res = subprocess.call(cmd_str, shell=True)
                return res
            except subprocess.CalledProcessError as e:
                print((e.message))

            except:
                raise
            else:
                pass
        # print(res)

    instance = None

    def __init__(self, classname):
        if not VnfLcmLog.instance:
            VnfLcmLog.instance = VnfLcmLog.__VnfLcmLog(classname)
        else:
            VnfLcmLog.instance.classname = classname

    def __getattr__(self, classname):
        return getattr(self.instance, classname)
