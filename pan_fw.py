#!/usr/bin/python3
import time
import json
import requests
import xmltodict
from logger import init_logging, logger

# Setup logging
init_logging()
requests.packages.urllib3.disable_warnings()

# logger.info = lambda _ : print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)


def fw_key(fw_ip, uname, pwd):
    api_url = f"https://{fw_ip}/api"
    api_prm = {
        "type": "keygen",
        "user": {uname},
        "password": {pwd}
    }

    for _ in range(3):
        try:
            logger.info(f"PAN-OS API: Connection Requested, Firewall {fw_ip}")
            response = requests.request(
                "GET", url=api_url, params=api_prm, verify=False, timeout=3)
        except Exception:
            logger.error(
                f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
            time.sleep(2)
        else:
            logger.info(
                f"PAN-OS API: Connection Succeeded, Firewall {fw_ip} Key Retrieved")
            key = xmltodict.parse(response.text)["response"]["result"]["key"]
            return key
    return False


def fw_gp_ext(fw_ip, fw_key):
    api_url = f"https://{fw_ip}/api"
    api_prm = {
        "key": fw_key,
        "type": "op",
        "cmd": "<show><global-protect-gateway><current-user/></global-protect-gateway></show>"
    }

    try:
        logger.info(
            f"PAN-OS API: Request GP-Gateway Connected Users, Firewall {fw_ip}")
        response = requests.request(
            "GET", url=api_url, params=api_prm, verify=False, timeout=3)
    except Exception:
        logger.error(
            f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
        raise ValueError(
            f" PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
    else:
        logger.info(
            f"PAN-OS API: Analyzing GP-Gateway Connected Users, Firewall {fw_ip}")
        result = xmltodict.parse(response.text)["response"]["result"]
        gp_users = []
        if result:
            logger.info(
                f"PAN-OS API: Found Users Connected to GP-Gateway, Firewall {fw_ip}")
            if type(result["entry"]) == dict:
                result["entry"] = [result["entry"]]
            for _ in result["entry"]:
                user = dict()
                user["Username"] = _["username"]
                user["Client-Hostname"] = _["computer"]
                user["Client-OS"] = _["client"]
                user["Client-Source-IP"] = _["client-ip"]
                gp_users.append(user)
                logger.info(
                    f"PAN-OS API: User \"{user['Username']}\" Connected to GP-Gateway, Firewall {fw_ip}")
        else:
            logger.info(
                f"PAN-OS API: NO Users Connected to GP-Gateway, Firewall {fw_ip}")
        gp_connected_user_data = dict()
        for entry in gp_users:
            if entry['Username'] in gp_connected_user_data.keys():
                gp_connected_user_data[entry['Username']].append(entry)
            else:
                gp_connected_user_data[entry['Username']] = [entry]
        return gp_connected_user_data


def fw_gp_lst(gp_ext):
    gp_users = []
    for _ in gp_ext:
        gp_users.append(_["Username"])
    return gp_users
