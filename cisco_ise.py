#!/usr/bin/python3
import datetime
import base64
import json
import requests
import time
from logger import init_logging, logger

import traceback

# Setup config
init_logging()

requests.packages.urllib3.disable_warnings()

# Globally cached lists (all_users, all_groups)
all_users = dict()
all_groups = dict()

# def log4y(_):
# return print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)


def ise_auth(uname, pwd):
    logger.info(f"Calculating Cisco ISE API Basic Auth Token")
    token = base64.b64encode(f"{uname}:{pwd}".encode('utf-8')).decode("ascii")
    return f"Basic {token}"


def ise_api_call(ise_ip, ise_auth, path, method="GET", ise_port=9060, payload=None):
    """
    Construct and do ISE API Call
    """
    api_headers = {
        "Authorization": ise_auth,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    api_url_base = f"https://{ise_ip}:{str(ise_port)}"
    api_url = f"{api_url_base}{path}"
    try:
        if method in ["POST", "PUT", "PATCH"]:
            result = requests.request(
                method,
                url=api_url,
                headers=api_headers,
                verify=False,
                data=payload,
                timeout=3
            )
        else:
            result = requests.request(
                method,
                url=api_url,
                headers=api_headers,
                verify=False,
                timeout=3
            )

    except Exception:
        logger.error(f"Error occurred while trying API call for ISE {ise_ip}")
        traceback.print_exc()
    return result


def ise_get_all_users(ise_ip, ise_auth):
    """
    ISE: Get all users (InternalUsers) on ISE
    """
    global all_users
    api_path = f"/ers/config/internaluser"

    for _ in range(3):
        try:
            logger.info(f"Cisco ISE API: Request All ISE Users, ISE {ise_ip}")
            response = ise_api_call(ise_ip, ise_auth, api_path)

        except Exception as e:
            logger.error(
                f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred")
            traceback.print_exc()
            time.sleep(1)
        else:
            logger.info(
                f"Cisco ISE API: Connection Succeeded, ISE {ise_ip} Users Retrieved")
            users_ext = response.json()["SearchResult"]["resources"]
            for _ in users_ext:
                all_users[_['name']] = _
            return all_users


def ise_get_user_details(ise_ip, ise_auth, user):
    api_path = f"/ers/config/internaluser/{user['id']}"
    try:
        logger.info(
            f"Cisco ISE API: Request ISE User {user['name']} Details, ISE {ise_ip}")
        response = ise_api_call(ise_ip, ise_auth, api_path)
    except Exception:
        logger.error(
            f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred.")
        traceback.print_exc()
    else:
        logger.info(
            f"Cisco ISE API: User {user['name']} Details Retrieved, ISE {ise_ip}")
    return response.json()


def ise_enrich_user(ise_ip: str, ise_auth: str, username: str) -> dict:
    global all_users
    try:
        if username not in all_users:
            all_users = ise_get_all_users(ise_ip, ise_auth)
        all_users[username] = ise_get_user_details(
            ise_ip, ise_auth, all_users[username])['InternalUser']
        user = all_users[username]
    except Exception as e:
        logger.error(
            f"Cisco ISE API: ISE {ise_ip} Unreachable or error occurred")
        traceback.print_exc()
        time.sleep(1)
    else:
        logger.info(
            f"Cisco ISE API: Connection Succeeded, User details for {username} Retrieved")
        return user
    return None


def ise_del_gp_users(ise_ip, ise_auth, gp_del_lst, all_users_grp):
    api_prm = {}
    api_hdr = {
        "Authorization": ise_auth,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for user in gp_del_lst:
        api_url = f"https://{ise_ip}:9060/ers/config/internaluser/name/{user}"
        api_payload = json.dumps({
            "InternalUser": {
                "name": user,
                "identityGroups": all_users_grp
            }
        })
        for _ in range(3):
            try:
                logger.info(
                    f"Cisco ISE API: Request User {user} Delete from GP Group, ISE {ise_ip}")
                response = requests.request(
                    "PUT", url=api_url, headers=api_hdr, data=api_payload, verify=False, timeout=3)
            except Exception:
                logger.info(
                    f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable")
                time.sleep(2)
            else:
                if (response.json()["UpdatedFieldsList"]["updatedField"][0]["field"]) == "identityGroups":
                    logger.info(
                        f"Cisco ISE API: User {user} Deleted from GP Group Successfully, ISE {ise_ip}")
                else:
                    logger.info(
                        f"Cisco ISE API: User {user} NOT Deleted from GP. Please check Manually, ISE {ise_ip}")
                break
    return True


def ise_add_grp_to_user(ise_ip: str,
                        ise_auth: str,
                        username: str,
                        gp_grp: str,
                        custom_attributes: dict = {}) -> bool:
    """
    ISE: Add Group to User (with optional update of Custom Attributes)
    """
    global all_groups
    # Enrich user details (if not already done) and get user
    u = ise_enrich_user(ise_ip, ise_auth, username)
    if u is None:
        logger.error(
            f"User {username} does not seem to exist. Aborting update")
        return False
    # Get group ID for group to update
    if gp_grp not in all_groups.keys():
        ise_get_all_groups(ise_ip, ise_auth)
        if gp_grp not in all_groups.keys():
            logger.error(
                f"Group with name {gp_grp} not found on ISE. User will not be updated")
            return False

    user_groups = u['identityGroups'].split(",")
    gp_grp = all_groups[gp_grp]
    if gp_grp['id'] not in user_groups:
        user_groups.append(gp_grp['id'])
    u['identityGroups'] = (',').join(user_groups)

    api_path = f"/ers/config/internaluser/{u['id']}"
    api_payload_dict = {
        "InternalUser": {
            "name": u['name'],
            "id": u["id"],
            "identityGroups": u['identityGroups']
        }}
    if len(custom_attributes.keys()):
        api_payload_dict['InternalUser']['customAttributes'] = custom_attributes
    api_payload = json.dumps(api_payload_dict)
    for _ in range(3):
        try:
            logger.debug(
                f"API Payload: {json.dumps(json.loads(api_payload), indent=2)}")
            res = ise_api_call(ise_ip, ise_auth, api_path,
                               method="PUT", payload=api_payload)
        except Exception as e:
            logger.error(
                f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred.")
            traceback.print_exc()
        else:
            logger.debug(
                f"Status Code: {res.status_code}, Response Body: {json.dumps(res.json(), indent=2)}")
            logger.info(
                f"Group {gp_grp['name']} with ID {gp_grp['id']} added to User {u['name']}'s identityGroups")
            return True


def ise_del_grp_from_user(ise_ip: str,
                          ise_auth: str,
                          username: str,
                          gp_grp: str,
                          custom_attributes: dict = {}) -> bool:
    """
    ISE: Delete Group from User (with optional update of Custom Attributes)
    """
    global all_groups
    # Enrich user details (if not already done) and get user
    u = ise_enrich_user(ise_ip, ise_auth, username)
    if u is None:
        logger.error(
            f"User {username} does not seem to exist. Aborting update")
        return False
    # Get group ID for group to update
    if gp_grp not in all_groups.keys():
        ise_get_all_groups(ise_ip, ise_auth)
        if gp_grp not in all_groups.keys():
            logger.error(
                f"Group with name {gp_grp} not found on ISE. User will not be updated")
            return False

    user_groups = list(set(u['identityGroups'].split(",")))
    gp_grp = all_groups[gp_grp]
    if gp_grp['id'] in user_groups:
        user_groups.remove(gp_grp['id'])
        u['identityGroups'] = (',').join(list(set(user_groups)))
    else:
        logger.info(
            f"User {u['name']} not a member of group {gp_grp['name']}. Not making any changes")
        return False

    api_path = f"/ers/config/internaluser/{u['id']}"
    api_payload_dict = {
        "InternalUser": {
            "name": u['name'],
            "id": u["id"],
            "identityGroups": u['identityGroups']
        }}
    if len(custom_attributes.keys()):
        api_payload_dict['InternalUser']['customAttributes'] = custom_attributes
    api_payload = json.dumps(api_payload_dict)
    for _ in range(3):
        try:
            logger.debug(
                f"API Payload: {json.dumps(json.loads(api_payload), indent=2)}")
            res = ise_api_call(ise_ip, ise_auth, api_path,
                               method="PUT", payload=api_payload)
        except Exception as e:
            logger.error(
                f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred.")
            traceback.print_exc()
        else:
            logger.debug(
                f"Status Code: {res.status_code}, Response Body: {json.dumps(res.json(), indent=2)}")
            logger.info(
                f"Group {gp_grp['name']} with ID {gp_grp['id']} removed from User {u['name']}'s identityGroups")
            return True


def ise_add_gp_users(ise_ip, ise_auth, gp_add_lst, gp_all_ext):
    """
    ise: add user to ise gp group
    """
    api_prm = {}
    gp_add_ext = []
    # modified in 20dec2022
    # loop in loop -- check if something easier
    for _ in gp_all_ext:
        for user in gp_add_lst:
            if _["username"] == user:
                gp_add_ext.append(_)

    gp_all_ext = gp_add_ext

    for _ in gp_all_ext:
        user = _["username"]
        api_url = f"https://{ise_ip}:9060/ers/config/internaluser/name/{user}"
        api_payload = json.dumps({
            "internaluser": {
                "name": _["username"],
                "identitygroups": "09e059a0-5b2c-11ed-bd89-96cdf119828a,1adbe260-5b2c-11ed-bd89-96cdf119828a",
                "customattributes": {
                    "paloalto-client-hostname": _["client-hostname"],
                    "paloalto-client-os": _["client-os"],
                    "paloalto-client-source-ip": _["client-source-ip"]
                }
            }
        })
        for _ in range(3):
            try:
                logger.info(
                    f"cisco ise api: request user {user} add to gp group, ise {ise_ip}")
                response = requests.request(
                    "put", url=api_url, headers=api_hdr, data=api_payload, verify=false, timeout=3)
            except exception:
                logger.info(
                    f"cisco ise api: connection failure, ise {ise_ip} unreachable")
                time.sleep(2)
            else:
                if (response.json()["updatedfieldslist"]["updatedfield"][0]["field"]):
                    logger.info(
                        f"cisco ise api: user {user} added to gp group successfully, ise {ise_ip}")
                else:
                    logger.info(
                        f"cisco ise api: user {user} not deleted from gp. please check manually, ise {ise_ip}")
                break
    return true


def ise_get_all_groups(ise_ip: str, ise_auth: str):
    """
    get all groups (identitygroup)s from ise

    args:
    - ise_ip: ip address of ise
    - ise_auth: ise auth token
    """
    global all_groups
    api_path = "/ers/config/identitygroup"
    for _ in range(3):
        try:
            logger.info(f"cisco ise api: request all ise groups, ise {ise_ip}")
            response = ise_api_call(ise_ip, ise_auth, api_path)
        except exception:
            logger.error(
                f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred")
            traceback.print_exc()
            time.sleep(2)
        else:
            grp_list = response.json()["SearchResult"]["resources"]
            for _ in grp_list:
                all_groups[_['name']] = _
            return all_groups


def ise_create_user(ise_ip, ise_auth, ucount):
    api_prm = {}
    api_hdr = {
        "Authorization": ise_auth,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    api_payload = {}

    for _ in range(1, ucount):
        api_url = f"https://{ise_ip}:9060/ers/config/internaluser/name/user{_}"
        response = requests.request(
            "DELETE", url=api_url, headers=api_hdr, verify=False, timeout=3)
        logger.info(f"Cisco ISE API: User \"user{_}\" Deleted")

        api_url = f"https://{ise_ip}:9060/ers/config/internaluser"
        api_payload = json.dumps({
            "InternalUser": {
                "name": f"user{_}",
                "description": f"user{_}, Password123",
                "enabled": True,
                "email": f"user{_}@asiacell.com",
                "password": "Password123",
                "firstName": "User",
                "lastName": _,
                "changePassword": False,
                "identityGroups": "09e059a0-5b2c-11ed-bd89-96cdf119828a",
                "expiryDateEnabled": False,
                "passwordIDStore": "Internal Users",
                "customAttributes": {}
            }
        })
        response = requests.request(
            "POST", url=api_url, headers=api_hdr, data=api_payload, verify=False, timeout=3)
        logger.info(f"Cisco ISE API: User \"user{_}\" Created")
    return True
