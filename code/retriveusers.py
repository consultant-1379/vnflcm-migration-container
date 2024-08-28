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

import sys
import json
import requests
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from vnflcmlog import VnfLcmLog


class EnmAndEvnfmUsers:

    def __init__(self):
        self.log = VnfLcmLog('RetrieveUsers')
        self.enm_host = sys.argv[1]
        self.enm_user_name = sys.argv[2]
        self.enm_user_password = sys.argv[3]
        self.evnfm_host = sys.argv[4]
        self.evnfm_user_name = sys.argv[5]
        self.evnfm_user_password = sys.argv[6]
        self.evnfm_client = sys.argv[7]
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.session = requests.Session()
        self.role = "E-VNFM Super User Role"

    def generate_cookie(self):
        params = {'IDToken1': self.enm_user_name, 'IDToken2': self.enm_user_password}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        url = ("https://{}/login").format(self.enm_host)
        try:
            self.log.info("proceeding with generation of cookie")
            cookie_req = self.session.post(url, params=params, headers=headers, verify=False)
            cookie_req.raise_for_status()
            self.log.info("cookie generated")
        except requests.exceptions.ConnectionError:
            self.log.error("ConnectionError in generating cookie")
            print((self.enm_host + " " + "connection error"))
            exit(1)
        except requests.exceptions.HTTPError as err:
            self.log.error("unable to generate tokens:: {}".format(self.getMaskedString(str(err))))
            print(("unable to generate tokens", self.getMaskedString(str(err))))
            exit(1)
        except Exception as err:
            print(("Exception in generating cookie:: {}".format(self.getMaskedString(str(err)))))
            self.log.error("Exception in generating cookie:: {}".format(self.getMaskedString(str(err))))
            exit(1)

    def enm_user_list_and_privileges(self):
        self.generate_cookie()
        list_url = ("https://{}/oss/idm/usermanagement/users").format(self.enm_host)
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        try:
            self.log.info("proceeding with listing enm user and their privileges")
            list_req = self.session.get(list_url, headers=headers, verify=False)
            list_req.raise_for_status()
            list_res = list_req.json()
            self.enm_user_data = []
            for users in list_res:
                user = users.get("username", "")
                previlige_url = ("https://{}/oss/idm/usermanagement/users/{}/privileges").format(self.enm_host, user)
                previlige_req = self.session.get(previlige_url, headers=headers, data={}, verify=False)
                previlige_req.raise_for_status()
                previlige_res = previlige_req.json()
                for data in previlige_res:
                    role = data.get("role", "")
                    if "vnflcm".upper() in role:
                        # print("verify the user name",users.get("username",""))
                        # print("verify the status",users.get("status",""))
                        # print("verify the surname/lastname",users.get("surname",""))
                        # print("verify the email",users.get("email",""))
                        # print("verify the role",data.get("role",""))
                        current_user_data = (users.get("username", ""), data.get("role", ""), users.get("name", ""), users.get("status", ""), users.get("surname", ""), users.get("email", ""))
                        self.enm_user_data.append(current_user_data)
            if not self.enm_user_data:
                print("No users with the VNFLCM roles are present in ENM")
                self.log.info("No users with the VNFLCM roles are present in ENM")
                exit(1)
            print("ENM users with the VNFLCM as roles:")
            print((json.dumps(self.enm_user_data, indent=4)))
        except requests.exceptions.ConnectionError as err:
            print((self.enm_host + " " + "connection error", self.getMaskedString(str(err))))
            exit(1)
        except requests.exceptions.HTTPError as err:
            print(("unable to list" + " " + self.enm_host + " " + "users", self.getMaskedString(str(err))))
            exit(1)
        except Exception as err:
            print(("Exception in enm_user_list_and_privileges:: {}".format(self.getMaskedString(str(err)))))
            self.log.error("Exception in enm_user_list_and_privileges:: {}".format(self.getMaskedString(str(err))))
            exit(1)

    def generate_token(self):
        data = {'username': self.evnfm_user_name, 'password': self.evnfm_user_password, 'grant_type': 'password', 'client_id': self.evnfm_client}
        evnfm_url = ("https://{}/auth/realms/master/protocol/openid-connect/token").format(self.evnfm_host)
        try:
            self.log.info("proceeding with generation of token")
            token_response = requests.post(evnfm_url, data=data, verify=False)
            token_response.raise_for_status()
            token_response = token_response.json()
            self.access_token = token_response["access_token"]
            self.log.info("Token generated.")
        except requests.exceptions.ConnectionError as err:
            print((self.evnfm_host + " " + "connection error", self.getMaskedString(str(err))))
            exit(1)
        except requests.exceptions.HTTPError as err:
            print(("unable to generate token for" + self.evnfm_host, self.getMaskedString(str(err))))
            exit(1)

    def list_evnfm_users(self):
        self.generate_token()
        list_evnfm_url = ("https://{}/auth/admin/realms/master/users").format(self.evnfm_host)
        headers = {'Content-type': 'application/json', 'Authorization': 'Bearer {}'.format(self.access_token)}
        try:
            self.log.info("Proceeding with listing evnfm users")
            list_user_response = requests.get(list_evnfm_url, headers=headers, verify=False)
            list_user_response = list_user_response.json()
            print("Users in EVNFM:")
            print((json.dumps(list_user_response, indent=4)))
            self.log.info("users in evnfm listed successfully")
        except requests.exceptions.ConnectionError as err:
            print(("connection error", self.getMaskedString(str(err))))
            exit(1)
        except requests.exceptions.HTTPError as err:
            print(("unable to list existing users from evnfm", self.getMaskedString(str(err))))
            exit(1)

    def create_evnfm_users(self):
        self.generate_token()
        list_evnfm_url = ("https://{}/auth/admin/realms/master/users").format(self.evnfm_host)
        headers = {'Content-type': 'application/json', 'Authorization': 'Bearer {}'.format(self.access_token)}
        try:
            self.log.info("Proceeding with evnfm user creation.")
            for idx, val in enumerate(self.enm_user_data):
                user_name = val[0]
                role = val[1]
                name = val[2]
                status = val[3]
                surname = val[4]
                email = val[5]
                if status == "enabled":
                    status = "true"
                else:
                    status = "false"

                data = ('{{"enabled":"{}","username":"{}","email":"{}","firstName":"{}","lastName":"{}"}}').format(status, user_name, email, name, surname)
                list_user_response = requests.post(list_evnfm_url, headers=headers, data=data, verify=False)
                status_code = list_user_response.status_code
                if status_code == 201:
                    self.log.info("evnfm user creation is successful for the user {}".format(user_name))
                    print(("{} is created in evnfm Idam".format(user_name)))
                    get_user_id_url = ("https://{}/auth/admin/realms/master/users?username={}").format(self.evnfm_host, user_name)
                    user_response = requests.get(get_user_id_url, headers=headers, verify=False)
                    user_response = user_response.json()
                    for user in user_response:
                        user_id = user.get("id", "")
                        self.user_role_mappings(user_id)
                elif status_code == 409:
                    self.log.info("evnfm user creation status code obtained is 409")
                    print(("{} user already exists in evnfm idam".format(user_name)))
                else:
                    self.log.error("unable to create user {}in evnfm idam".format(user_name))
                    print(("Unable to create user {} in evnfm idam".format(user_name)))
        except requests.exceptions.ConnectionError as err:
            print(("connection error", self.getMaskedString(str(err))))
            self.log.error("connection error")
            exit(1)
        except requests.exceptions.HTTPError as err:
            print(("unable to create users in evnfm", self.getMaskedString(str(err))))
            self.log.error("unable to create users in evnfm")
            exit(1)

    def get_super_user_role_id(self):
        self.generate_token()
        role_url = ("https://{}/auth/admin/realms/master/roles/{}").format(self.evnfm_host, self.role)
        headers = {'Content-type': 'application/json', 'Authorization': 'Bearer {}'.format(self.access_token)}
        try:
            self.log.info("proceeding to get super user role id")
            get_role_response = requests.get(role_url, headers=headers, verify=False)
            get_role_response = get_role_response.json()
            self.role_id = get_role_response["id"].replace("u'", "\"")
            print(("evnfm super user role id is", self.role_id))
            self.log.info("evnfm super user role id obtained successfully")
        except requests.exceptions.ConnectionError as err:
            print(("connection error", self.getMaskedString(str(err))))
            self.log.error("connection error in getting super user role id")
            exit(1)
        except requests.exceptions.HTTPError as err:
            print(("unable to get EVNFM super user role from evnfm", self.getMaskedString(str(err))))
            exit(1)

    def user_role_mappings(self, user_id):
        self.generate_token()
        self.get_super_user_role_id()
        role_mapping_url = ("https://{}/auth/admin/realms/master/users/{}/role-mappings/realm").format(self.evnfm_host, user_id)
        headers = {'Content-type': 'application/json', 'Authorization': 'Bearer {}'.format(self.access_token)}
        try:
            self.log.info("proceeding in user role mappings")
            data = ('[{{"id": "{}", "name": "{}","clientRole": "false", "composite": "false", "containerId": "master"}}]').format(self.role_id, self.role)
            role_mapping_response = requests.post(role_mapping_url, headers=headers, data=data, verify=False)
            role_mapping_response = role_mapping_response.status_code
            if role_mapping_response == 204:
                self.log.info("{} is mapped to user {}".format(self.role_id, user_id))
                print(("{} is mapped to the user {} successfully".format(self.role_id, user_id)))
                self.log.debug("{} is mapped to the user {} successfully".format(self.role_id, user_id))
            else:
                print(("Please assgin roles manully for the user {}".format(user_id)))
        except requests.exceptions.ConnectionError as err:
            print(("connection error", self.getMaskedString(str(err))))
            self.log.error("connection error in user role mappings")
            exit(1)
        except requests.exceptions.HTTPError as err:
            print(("unable to map user to the super user role in EVNFM",self.getMaskedString(str(err))))
            self.log.error("unable to map user to the super user role in EVNFM")
            exit(1)

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
        except re.error as e:
            self.log.exception("Exception : %s" %str(e),self)
        except Exception as Err:
            self.log.exception("error in masking :%s" %str(Err),self)
        return str(message)


def main():
    retrive_user = EnmAndEvnfmUsers()
    retrive_user.enm_user_list_and_privileges()
    retrive_user.list_evnfm_users()
    retrive_user.create_evnfm_users()


if __name__ == "__main__":
    main()
