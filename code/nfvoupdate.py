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
import base64
import ssl
import urllib.request, urllib.error, urllib.parse
import json
import sys
import subprocess
import re

sys.path.insert(1, '/opt/ericsson/ERICvnflcmadmincli_CXP9033981/')
from common.vnflcmlog import VnfLcmLog


class NfvoUpdate:

    def __init__(self):
        self.log = VnfLcmLog("NfvoUpdate[Migration]")
        self.eo_host_name = sys.argv[1]
        self.eo_user_name = sys.argv[2]
        self.eo_password = sys.argv[3]
        self.evnfm_host_name = sys.argv[4]
        self.evnfm_user_name = sys.argv[5]
        self.evnfm_password = sys.argv[6]
        self.eo_admin_tenant = sys.argv[7]
        self.encoded_eo_userName_password = ""
        self.tenant_id = ""
        self.nfvo_response = ""
        self.output_file = "/vnflcm-ext/.restoreVnflcmService.txt"
        self.status = ""

    def get_nfvo(self):
        print("Getting nfvo details")
        self.log.info("Getting nfvo details")
        self.status = "get_nfvo():Processing"
        state_file = open(self.output_file, 'w')
        state_file.write(self.status + '\n')
        url = "http://localhost:8080/vnflcmservice/nfvos"
        header = {'Accept': 'application/json', 'X-Tor-UserID': 'vnflcm-cli'}
        status_code, self.nfvo_response = self.rest_client(url, 'GET', header, '', state_file)
        print ("rest call done")
        self.log.info("Status code of GET nfvo:: {}".format(status_code))
        self.log.info("Response of GET nfvo:: {}".format(self.getMaskedString(str(self.nfvo_response))))
        if status_code == 200:
            response = json.loads(self.nfvo_response)
            nfvoPresent = 0
            for nfvo in response:
                if nfvo['configType'] == "NFVO" and nfvo['nfvoInUse'] == "Y":
                    self.log.info("NFVO with nfvoInUse exists")
                    nfvoPresent = 1
                    self.filteredjson = json.dumps(nfvo)
                    subscription_id = nfvo["subscriptionId"]
                    # print("Subscription id", subscription_id)
                    tenant = nfvo["connectionDetails"]
                    for tenantid in tenant:
                        self.tenant_id = tenantid["tenantId"]
                        # print("Tenant id", self.tenant_id)
                    self.log.info("Subscription ID is:: {}, tenant is:: {} and tenantid is:: {}".format(subscription_id, tenant, self.tenant_id))
                    self.update_vnfm_and_nvfo(subscription_id, state_file)
                    break
            if nfvoPresent == 0:
                self.log.info("NFVO with nfvoInUse do not exists")
                print("There are no NFVO's which are in use")
                self.status = "nfvo_update:Success-NoUpdateRequired"
                state_file.write(self.status)
                return 1
        elif status_code == None:
            self.log.info("There are no NFVO's configured")
            print("There are no NFVO's configured")
            self.status = "nfvo_update:Success-NoUpdateRequired"
            state_file.write(self.status)
            return 1
        else:
            self.log.info("Failed in getting nfvo details")
            print("Failed in getting nfvo details")
            self.status = "nfvo_update:Failed"
            state_file.write(self.status)
            exit(1)
        state_file.close()

    def update_vnfm_and_nvfo(self, subscription_id, state_file):
        self.log.info("Fetching EO specific data. In update vnfm and nfvo")
        print("Fetching EO specific data")
        self.status = "update_vnfm_and_nvfo():Processing"
        state_file.write(self.status + '\n')
        self.encoded_eo_userName_password = self.encode_username_password()
        url = "https://{}/ecm_service/vnfms/{}".format(self.eo_host_name, subscription_id)
        if self.eo_admin_tenant != "dummy":
            self.log.info("EO Admin Tenant:: {}".format(self.eo_admin_tenant))
            self.tenant_id == self.eo_admin_tenant
        self.log.info("Tenant ID for GET VNFM:: {}".format(self.tenant_id))
        header = {'Content-type': 'application/json', 'Authorization': 'Basic {}'.format(self.encoded_eo_userName_password), 'TenantId': self.tenant_id}
        try:
            status_code, response = self.rest_client(url, 'GET', header, '', state_file)
            self.log.info("Status code of GET vnfm:: {}".format(status_code))
            self.log.info("Response of GET vnfm:: {}".format(self.getMaskedString(str(response))))
            if status_code == 200:
                response = json.loads(response)
                endpoints_details = json.loads(str(response["data"]["vnfm"]["endpoints"])[1:-1].replace("u'", "\"").replace("'", "\"").replace('True', 'true').replace('False', 'false'))
                vnfm_endpoint_name = endpoints_details["name"]
                vnfm_endpoint_port = "443"
                vnfm_endpoint_test_uri = "/vnflcm"
                vnfm_security_type = "HTTPS"
                self.update_vnfm(subscription_id, vnfm_endpoint_name, vnfm_endpoint_port, vnfm_endpoint_test_uri, vnfm_security_type, state_file)
            else:
                self.log.info("Failed to get EO related data")
                print("Failed to get EO related data")
                self.status = "nfvo_update:Failed"
                state_file.write(self.status + '\n')
                exit(1)
        except Exception as err:
            self.log.exception("Failed in updating VNFM:: {}".format(str(err)))
            print("Failed in updating VNFM")
            self.status = "nfvo_update:Failed"
            state_file.write(self.status)
            exit(1)

    # Encode EO username and password using base64 encoder.
    def encode_username_password(self):
        self.log.info("Encoding username and password")
        username_password = self.eo_user_name + ":" + self.eo_password
        username_bytes = base64.b64encode(username_password.encode('utf-8'))
        return username_bytes.decode('utf-8')

    def rest_client(self, url, method, header, datal, state_file):
        self.status = "rest_client():Processing"
        state_file.write(self.status + '\n')
        response_data = None
        status_code = 503
        try:
            print("inside try 1")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            request = urllib.request.Request(url, data=datal.encode())
            for key, value in list(header.items()):
                request.add_header(key, value)

            request.get_method = lambda: method
            url = opener.open(request)
            response_data = url.read()
            print("response data: {}".format(self.getMaskedString(str(response_data))))
            status_code = url.getcode()
        except urllib.error.HTTPError as exp:
            if exp.code == 404:
                return None, None
            else:
                print(("HTTP Error. Reason is : " + str(exp.reason)))
                self.status = "nfvo_update:Failed"
                state_file.write(self.status + '\n')
                if hasattr(exp, "errno"):
                    exit(exp.errno)
                else:
                    exit(1)

        except urllib.error.URLError as exp1:
            print(("URL Error. Reason is : " + str(exp1.reason)))
            self.status = "nfvo_update:Failed"
            state_file.write(self.status + '\n')
            if hasattr(exp1, "errno"):
                exit(exp1.errno)
            else:
                exit(1)

        except Exception as Err:
            print(("error in send url: %s" % str(Err), self))
            self.status = "nfvo_update:Failed"
            state_file.write(self.status + '\n')
            if hasattr(Err, "errno"):
                exit(Err.errno)
            else:
                exit(1)

        return status_code, response_data

    def getMaskedString(self, message):
        message = message.replace(" ","")
        try:
            if message.__contains__("Password") or message.__contains__("password"):
                message = re.sub('password[\":\'a-z0-9@$%&#!=]*', 'Password: *******',message,flags=re.I)
            if message.__contains__("token") or message.__contains__("Token"):
                message= re.sub('token[0-9]\":[a-z0-9\s!@#$%^&\*()_+\-=\[\]{};\':\"\|,,.<>\/?\"]*', 'token: *********}',message,flags=re.I)
                message= re.sub('token[0-9]\=[a-z0-9\s!@#$%^&\*()_+\-=\[\]{};\':\"\|,,.<>\/?\"]*', 'token: *********}',message,flags=re.I)
            if message.__contains__("sensitiveBlock"):
                message= re.sub('sensitiveBlock\":[a-z0-9\s!@#$%^&\*()_+\-=\[\]{};\':\"\|,,.<>\/?\"]*', 'sensitiveBlock: *********}',message,flags=re.I)
            if message.__contains__("credentials") or message.__contains__("Credentials"):
                message= re.sub('credentials\":[a-z0-9\s!@#$%^&\*_+\-=.\"]*', 'credentials: *********',message,flags=re.I)
        except re.error as e:
            self.log.exception("Exception : %s" %str(e),self)
        except Exception as Err:
            self.log.exception("error in masking :%s" %str(Err),self)
        return str(message)

    def update_vnfm(self, subscription_id, vnfm_endpoint_name, vnfm_endpoint_port, vnfm_endpoint_test_uri, vnfm_security_type, state_file):
        self.log.info("Updating VNFM")
        print("Updating VNFM")
        self.status = "update_vnfm():Processing"
        state_file.write(self.status + '\n')
        url = "https://{}/ecm_service/vnfms/{}".format(self.eo_host_name, subscription_id)
        header = {'Content-type': 'application/json', 'Authorization': 'Basic {}'.format(self.encoded_eo_userName_password), 'TenantId': self.tenant_id}
        data = {"endpoints": [{"name": vnfm_endpoint_name, "ipAddress": self.evnfm_host_name, "port": vnfm_endpoint_port, "testUri": vnfm_endpoint_test_uri}],
                "defaultSecurityConfig": {"securityType": vnfm_security_type}, "authIpAddress": self.evnfm_host_name, "authPort": vnfm_endpoint_port,
                "authPath": "/auth/v1", "authUserName": self.evnfm_user_name, "authPassword": self.evnfm_password, "authType": "EVNFM"}
        self.log.info("Data for Update VNFM:: name-{}, ipAddress-{}, port-{}, testUri-{}, securityType-{}, authIpAddress-{}, authPort-{}, authUserName-{}".
                      format(vnfm_endpoint_name, self.evnfm_host_name, vnfm_endpoint_port, vnfm_endpoint_test_uri, vnfm_security_type, self.evnfm_host_name, vnfm_endpoint_port, self.evnfm_user_name))
        data = json.dumps(data)
        status_code, response = self.rest_client(url, 'PATCH', header, data, state_file)
        self.log.info("Status code of PATCH vnfm:: {}".format(status_code))
        self.log.info("Response of PATCH vnfm:: {}".format(self.getMaskedString(str(response))))
        response = json.loads(response)
        if response["status"]["reqStatus"] == 'SUCCESS':
            self.log.info("reqStatus is Success in Update VNFM")
            self.configure_pib_param(self.evnfm_host_name, state_file)
        else:
            self.log.info("Updating nfvo_update to Failed in Update VNFM")
            self.status = "nfvo_update:Failed"
            state_file.write(self.status + '\n')
            exit(1)

    def execute_pib_cmd(self, create_cmd, update_cmd):
        self.log.info("Executing pib command")
        resp_code = self.execute_command(create_cmd)
        if resp_code != 0:
            resp_code = self.execute_command(update_cmd)
            if resp_code == 0:
                return "True"
            else:
                return "False"
        else:
            return "True"

    def configure_pib_param(self, enm_host_name, state_file):
        self.log.info("Configuring pib command")
        create_cmd = self.cmd_generator("create", "enmHostName", enm_host_name)
        update_cmd = self.cmd_generator("update", "enmHostName", enm_host_name)
        resp1 = self.execute_pib_cmd(create_cmd, update_cmd)
        if resp1 == "True":
            self.log.info("Pib param enmHostName configured successfully")
            print("Pib param enmHostName configured successfully")
            self.status = "nfvo_update:Success"
            state_file.write(self.status)
        else:
            self.log.info("Pib param enmHostName FAILED to configure")
            print("Pib param enmHostName FAILED to configure")
            self.status = "nfvo_update:Failed"
            state_file.write(self.status)

    def execute_command(self, cmd_str):
        self.log.info("Executing command:: {}".format(str(cmd_str)))
        try:
            res = subprocess.call(cmd_str, shell=True)
            return res
        except subprocess.CalledProcessError as Err:
            self.log.error("Error in execute command:: {}".format(str(Err)))
            if hasattr(Err, "errno"):
                exit(Err.errno)
            else:
                exit(1)
        except Exception as Err:
            self.log.error("Error in execute command:: {}".format(str(Err)))
            print(("error in execute command: %s" % str(Err)))
            if hasattr(Err, "errno"):
                exit(Err.errno)
            else:
                exit(1)

    def cmd_generator(self, type, param, input):
        self.log.info("Generating command with type:: {}, param:: {} and input:: {}".format(type, param, input))
        try:
            return "/usr/bin/python2 /ericsson/pib-scripts/etc/config.py" + " " + type + " " + "--app_server_address localhost:8080 --name=" + param + " --value=" + input + " --type=String --scope=GLOBAL " + ">/dev/null"
        except Exception as Err:
            print(("Exception in cmd_generator : %s" % str(Err)))

    def main(self):
        self.get_nfvo()


if __name__ == "__main__":
    nfvoUpdate = NfvoUpdate()
    nfvoUpdate.main()
