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

import subprocess
import requests
import json
import os
import sys
import re

sys.path.insert(1, '/opt/ericsson/ERICvnflcmadmincli_CXP9033981/')
from common.vnflcmlog import VnfLcmLog

log = VnfLcmLog("HealthCheck[Migration]")
vnfid = ""


def get_vnfid():
    log.info("Getting vnfid")
    sql_query = '''psql -h $POSTGRES_HOST -U $VNFLAF_POSTGRES_USER -w -p $POSTGRES_PORT -d vnflafdb -t -c " select vnfid from vnfs where instantiationstate > 0 limit 1"'''
    os.environ["PGPASSWORD"] = os.environ.get("VNFLAF_PGPASSWORD")
    p = subprocess.Popen([sql_query], shell=True, stdout=subprocess.PIPE)
    result = p.communicate()[0].decode()
    vnfid = result.replace("|", " ").strip()
    if vnfid:
        log.info("vnfid is:: {}".format(vnfid))
        get_vnf(vnfid)
    else:
        log.info("No instantiated vnfs present")
        print('No instantiated vnfs present')


def get_vnf(vnfid):
    try:
        log.info("Getting vnfs with id {}".format(vnfid))
        url = "http://localhost:8080/vnflcmservice/vnfInstance/vnfs/{}".format(vnfid)
        log.info("Url prepared :: {}".format(url))
        print(url)
        headers = {'Accept': 'application/json', 'X-Tor-UserID': 'vnflcm-cli'}
        response = requests.get(url, headers=headers, verify=False)
        data = response.json()
        print(getMaskedString(str(json.dumps(data, indent=4))))
    except Exception as err:
        log.error("Exception raised while getting vnf:: {}".format(str(err)))
        print("Failed in getting vnf")
        exit(1)

def getMaskedString(message):
        message = message.replace(" ","")
        try:
            if message.__contains__("Password") or message.__contains__("password"):
                message = re.sub('password[\":\'a-z0-9@$%&#!=]*', 'Password: *******',message,flags=re.I)
            if message.__contains__("token") or message.__contains__("Token"):
                message= re.sub('token[0-9]\":[a-z0-9\s!@#$%^&\*()_+\-=\[\]{};\':\"\|,,.<>\/?\"]*', 'token: *********}',message,flags=re.I)
                message= re.sub('token[0-9]\=[a-z0-9\s!@#$%^&\*()_+\-=\[\]{};\':\"\|,,.<>\/?\"]*', 'token: *********}',message,flags=re.I)
            if message.__contains__("sensitiveBlock"):
                message= re.sub('sensitiveBlock\":[a-z0-9\s!@#$%^&\*()_+\-=\[\]{};\':\"\|,,.<>\/?\"]*', 'sensitiveBlock: *********}',message,flags=re.I)
        except re.error as e:
            log.exception("Exception : %s" %str(e))
        except Exception as Err:
            log.exception("error in masking :%s" %str(Err))
        return str(message)

get_vnfid()
