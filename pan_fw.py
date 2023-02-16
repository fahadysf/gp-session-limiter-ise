#!/usr/bin/python3
import time
import json
import os
import pickle
import requests
import xmltodict
from logger import init_logging, logger
from config import get_config

# Setup config
config = get_config()

# Setup logging
init_logging()
logger.debug("Debug Logging Enabled")
requests.packages.urllib3.disable_warnings()


def get_active_fw(fw_ip: str, fw_ip2: str, api_key: str) -> str:
    """
    Determine the HA State and return the Active Firewall IP
    """
    try:
        api_url = f"https://{fw_ip}/api"
        api_prm = {
            "key": api_key,
            "type": "op",
            "cmd": "<show><high-availability><state/></high-availability></show>",
        }
        response = requests.request(
            "GET",
            url=api_url,
            params=api_prm,
            verify=False,
            timeout=10)
        fw1_result = xmltodict.parse(response.text)["response"]["result"]
        if fw1_result['enabled'] == 'yes':
            if fw1_result['group']['local-info']['state'] == 'active':
                active_fw = fw_ip
            elif fw1_result['group']['peer-info']['state'] == 'active':
                active_fw = fw_ip2
            else:
                logger.error("HA State Unknown based on FW1")
                raise Exception("HA State Unknown based on FW1")
        elif fw1_result['enabled'] == 'no':
            logger.debug(f"HA Disabled on FW1: {fw_ip}")
            active_fw = fw_ip
    except Exception as e:
        print(f"Error for FW1: {e}")
        fw1_result = 'error'
        api_url = f"https://{fw_ip2}/api"
        api_prm = {
            "key": api_key,
            "type": "op",
            "cmd": "<show><high-availability><state/></high-availability></show>",
        }
        try:
            response = requests.request(
                "GET",
                url=api_url,
                params=api_prm,
                verify=False,
                timeout=10)
            fw2_result = xmltodict.parse(response.text)["response"]["result"]
            if fw2_result['enabled'] == 'yes':
                if fw2_result['group']['local-info']['state'] == 'active':
                    active_fw = fw_ip2
                elif fw2_result['group']['peer-info']['state'] == 'active':
                    active_fw = fw_ip
                else:
                    active_fw = None
                    logger.error("HA State Unknown based on FW2")
            elif fw2_result['enabled'] == 'no':
                active_fw = fw_ip2
        except Exception as e:
            print(f"Error for FW2: {e}")
            active_fw = None
    logger.info(f"Active FW: {active_fw}")
    return active_fw


def fw_gp_ext(fw_ip, fw_key, ignore_cache: bool = False):

    global fw_data
    api_url = f"https://{fw_ip}/api"
    api_prm = {
        "key": fw_key,
        "type": "op",
        "cmd": "<show><global-protect-gateway><current-user/></global-protect-gateway></show>"
    }
    if not ignore_cache and ("fw_gp_sessions" in fw_data.keys() and fw_data["fw_gp_sessions_timestamp"] > time.time() - config['fw_gp_sessions_ttl']):
        logger.debug(
            f"FW GP Sessions data cache hit, freshness: {(time.time() - fw_data['fw_gp_sessions_timestamp']):.2f}s")
        gp_connected_user_data = fw_data["fw_gp_sessions"]
    else:
        logger.warning(
            f"FW GP Sessions data Cache Miss. Refreshing data from FW.")
        gp_connected_user_data = dict()
        try:
            logger.info(
                f"PAN-OS API: Request GP-Gateway Connected Users, Firewall {fw_ip}")
            response = requests.request(
                "GET", url=api_url, params=api_prm, verify=False, timeout=3)
        except Exception:
            logger.error(
                f"PAN-OS API: Connection Failure, Firewall {fw_ip} Unreachable. Exiting after 3 retries.")
            exit(1)
        else:
            logger.debug(
                f"PAN-OS API: Analyzing GP-Gateway Connected Users, Firewall {fw_ip}")
            result = xmltodict.parse(response.text)["response"]["result"]
            gp_users = []
            if result:
                logger.debug(
                    f"PAN-OS API: Found Users Connected to GP-Gateway, Firewall {fw_ip}")
                if type(result["entry"]) == dict:
                    result["entry"] = [result["entry"]]
                for _ in result["entry"]:
                    user = dict()
                    user["Username"] = _["username"].lower()
                    user["Client-Hostname"] = _["computer"]
                    user["Client-OS"] = _["client"]
                    user["Client-Source-IP"] = _["client-ip"]
                    user["Raw-Data"] = _
                    gp_users.append(user)
                    logger.debug(
                        f"PAN-OS API: User \"{user['Username']}\" Connected to GP-Gateway, Firewall {fw_ip}")
            else:
                logger.debug(
                    f"PAN-OS API: NO Users Connected to GP-Gateway, Firewall {fw_ip}")
            for entry in gp_users:
                if entry['Username'] in gp_connected_user_data.keys():
                    gp_connected_user_data[entry['Username']].append(entry)
                else:
                    gp_connected_user_data[entry['Username']] = [entry]
            fw_data["fw_gp_sessions"] = gp_connected_user_data
            fw_data["fw_gp_sessions_timestamp"] = time.time()
            save_fw_cache()
            logger.debug(
                f"Connected GP Users Data:\n {json.dumps(gp_connected_user_data, indent=2, sort_keys=True)}")
    return gp_connected_user_data


def fw_gp_lst(gp_ext):
    gp_users = []
    for _ in gp_ext:
        gp_users.append(_["Username"])
    return gp_users

# Implement cache for fw_key and fw_gp_ext


def save_fw_cache():
    global fw_data
    if "fw_key" in fw_data and not fw_data["fw_key"] is None:
        try:
            with open('data/fw_data.pickle', 'wb') as fd:
                pickle.dump(fw_data, fd, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            raise
    else:
        logger.error("FW Data Cache Not Saved. No Data to Save.")


def get_fw_cache():
    global fw_data
    if os.path.isfile('data/fw_data.pickle'):
        try:
            with open('data/fw_data.pickle', 'rb') as fd:
                fw_data = pickle.load(fd)
        except Exception:
            os.remove("data/fw_data.pickle")
            raise
    else:
        fw_data = {
            'fw_key': config['fw_credentials']['api_key'],
            'fw_key_timestamp': time.time(),
            'fw_gp_sessions': {},
            'fw_gp_sessions_timestamp': time.time(),
        }
        save_fw_cache()
    return fw_data


fw_data = get_fw_cache()
