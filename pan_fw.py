#!/usr/bin/python3
import time
import datetime
import requests
import xmltodict

requests.packages.urllib3.disable_warnings()
log4y = lambda _ : print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)

def fw_key(fw_ip, uname, pwd):
    api_url = f"https://{fw_ip}/api"
    api_prm = {
        "type": "keygen",
        "user": {uname},
        "password": {pwd}
    }
    api_hdr = {}
    api_pld = {}

    for _ in range(3):
        try:
            log4y(f"PAN-OS API: Connection Requested, Firewall {fw_ip}")
            response = requests.request("GET", url=api_url, params=api_prm, verify=False, timeout=3)
        except:
            log4y(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
            time.sleep(2)
        else:
            log4y(f"PAN-OS API: Connection Succeeded, Firewall {fw_ip} Key Retrieved")
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
    api_hdr = {}
    api_pld = {}
    try:
        log4y(f"PAN-OS API: Request GP-Gateway Connected Users, Firewall {fw_ip}")
        response = requests.request("GET", url=api_url, params=api_prm, verify=False, timeout=3)
    except:
        log4y(f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
        raise ValueError(f" PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable")
    else:
        log4y(f"PAN-OS API: Analyzing GP-Gateway Connected Users, Firewall {fw_ip}")
        result = xmltodict.parse(response.text)["response"]["result"]
        gp_users = []
        if result:
            log4y(f"PAN-OS API: Found Users Connected to GP-Gateway, Firewall {fw_ip}")
            if type(result["entry"]) == dict:
                result["entry"] = [result["entry"]]
            for _ in result["entry"]:
                user = dict()
                user["Username"] = _["username"]
                user["Client-Hostname"] = _["computer"]
                user["Client-OS"] = _["client"]
                user["Client-Source-IP"] = _["client-ip"]
                gp_users.append(user)
                log4y(f"PAN-OS API: User \"{user['Username']}\" Connected to GP-Gateway, Firewall {fw_ip}")
        else:
            log4y(f"PAN-OS API: NO Users Connected to GP-Gateway, Firewall {fw_ip}")
        return gp_users


def fw_gp_lst(gp_ext):
    gp_users = []
    for _ in gp_ext:
        gp_users.append(_["Username"])
    return gp_users

