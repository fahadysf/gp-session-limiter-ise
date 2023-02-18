#!/usr/bin/python3
import base64
import json
import requests
import time
import pickle
import os
import traceback
from logger import init_logging, logger
from config import get_config
from urllib.parse import urlparse

# Setup config
config = get_config()
init_logging()
# Specify level = 'DEBUG' if Debug data is needed.
# init_logging(level='DEBUG')

requests.packages.urllib3.disable_warnings()

# Globally cached lists (all_users, all_groups)
all_users_last_updated = 0
ha_device_last_update = 0
ise_active = config['ise_api_ip']


def load_user_data():
    if os.path.isfile('data/users.pickle'):
        try:
            with open('data/users.pickle', 'rb') as fd:
                all_users = pickle.load(fd)
        except Exception:
            os.remove("data/users.pickle")
            raise
    else:
        all_users = {}
    return all_users


def save_user_data():
    global all_users
    try:
        with open('data/users.pickle', 'wb') as fd:
            pickle.dump(all_users, fd, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        raise


def ise_auth(uname: str, pwd: str) -> str:
    """
    Calculates the Cisco ISE API basic authentication token.

    Parameters:
    - uname (str): The username to use for authentication.
    - pwd (str): The password to use for authentication.

    Returns:
    - str: The basic authentication token.
    """
    logger.info("Calculating Cisco ISE API Basic Auth Token")
    token = base64.b64encode(f"{uname}:{pwd}".encode('utf-8')).decode("ascii")
    return f"Basic {token}"


def ise_api_call(ise_ip: str, ise_auth: str, path: str,
                 method: str = "GET",
                 ise_port: int = 9060,
                 payload: str = None):
    """
    Parameters:
    - ise_ip (str): The IP address of the ISE server.
    - ise_auth (str): The ISE API authorization token.
    - path (str): The API path.
    - method (str): The HTTP method to use for the API call (defaults to "GET").
    - ise_port (int): The port of the ISE server (defaults to 9060).
    - payload (str): The payload for the API call (defaults to None).

    Returns:
    - result (requests.Request): The result of the API call.
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
        return None
    return result


def ise_get_node_details(node_name: str, ise_ip: str, ise_auth: str) -> dict:
    """Get the ISE node details.

    Args:
        ise_ip (str): _description_
        ise_auth (str): _description_

    Returns:
        dict: _description_
    """
    api_path = f"/ers/config/node/name/{node_name}"
    try:
        response = ise_api_call(ise_ip, ise_auth, api_path)
        logger.debug(f"ISE API: Node Details: {response.text}")
    except Exception as e:
        logger.error(f"Error occurred while trying API call for ISE {ise_ip}")
        raise
    return response.json()


def ise_get_pan_active(ise_auth: str) -> str:
    """
    Get the primary / active PAN status.
    """
    global config
    global ha_device_last_update
    global ise_active
    ise_ip = config['ise_api_ip']
    ise_ha_ip = config['ise_api_ha_ip']
    api_path = "/ers/config/node"

    # Check if we have the active PAN IP cached
    freshness = time.time() - ha_device_last_update
    if freshness < 60:
        logger.info(
            f"ISE API: Cached Active PAN IP: {ise_active}. Freshness: {freshness:.2f}s")
        return ise_active
    else:
        logger.debug(
            f'ISE API: Active Node refreshing because freshness is {freshness:.2f}s')
        try:
            response = ise_api_call(ise_ip, ise_auth, api_path)
            nodes = response.json()['SearchResult']['resources']
        except Exception as e:
            logger.error(
                f"ISE API: Connection Failure, ISE Unreachable on {ise_ip}. Error {e}. Trying other node")
            try:
                response = ise_api_call(ise_ha_ip, ise_auth, api_path)
                nodes = response.json()['SearchResult']['resources']
            except Exception as e:
                logger.error(
                    f"ISE API: Connection Failure, ISE Unreachable on both {ise_ip} and {ise_ha_ip}. Error {e}")
                raise
            else:
                working_ise_ip = ise_ha_ip
        else:
            working_ise_ip = ise_ip

        # Now try to get the details of the nodes and return the active PAN IP
        for node in nodes:
            try:
                ndata = ise_get_node_details(
                    node['name'], working_ise_ip, ise_auth)
                if ndata['Node']['papNode'] and ndata['Node']['primaryPapNode']:
                    if ndata['Node']['ipAddress'] in [ise_ip, ise_ha_ip]:
                        logger.info(
                            f"ISE API: Active PAN IP: {ndata['Node']['ipAddress']}")
                        ise_active = ndata['Node']['ipAddress']
                        ha_device_last_update = time.time()
                        return ise_active
            except Exception as e:
                logger.error(f"Couldn't get node details. Error {e}")
        return ise_active


def ise_get_all_users(ise_ip: str, ise_auth: str) -> dict:
    """
    Retrieves all users (InternalUsers) on ISE.

    Parameters:
    - ise_ip (str): The IP address of the ISE server.
    - ise_auth (str): The ISE API authorization token.

    Returns:
    - all_users: A dictionary containing all of the users on the ISE server.
    """
    global all_users
    global all_users_last_updated
    api_path = f"/ers/config/internaluser?size=100&page=1"
    if all_users_last_updated > time.time() - config['ise_all_user_refresh_ttl']:
        logger.warning(
            f"Cisco ISE API: Userlist already fresh. Not requesting from ISE {ise_ip}")
        return all_users
    continue_flag = True
    logger.info(f"Cisco ISE API: Request All ISE Users, ISE {ise_ip}")
    while continue_flag:
        for _ in range(3):
            try:
                response = ise_api_call(ise_ip, ise_auth, api_path)
            except Exception as e:
                logger.error(
                    f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred")
                traceback.print_exc()
                time.sleep(1)
            else:
                if response.status_code == 401:
                    logger.error(
                        "Cisco ISE API: Authentication Failure. Please check credentials")
                    logger.error(
                        f"Response: {response.text}, Status Code: {response.status_code}")
                    return {}
                elif response.status_code == 201:
                    logger.info(
                        f"Cisco ISE API: Connection Succeeded, ISE {ise_ip} Users Retrieved")
                users_ext = response.json()["SearchResult"]["resources"]
                logger.debug(f"Users Retrieved on page: {len(users_ext)}")
                for _ in users_ext:
                    if _['name'].lower() in all_users:
                        for k in _:
                            all_users[_['name'].lower()][k] = _[k]
                    else:
                        all_users[_['name'].lower()] = _
                if 'nextPage' in response.json()["SearchResult"]:
                    next_url = response.json(
                    )["SearchResult"]['nextPage']['href']
                    p = urlparse(next_url)
                    api_path = f"{p.path}?{p.query}"
                else:
                    logger.debug(f"All Users Count: {len(all_users.keys())}")
                    continue_flag = False
    all_users_last_updated = time.time()
    return all_users


def ise_get_user_details(ise_ip: str, ise_auth: str, user: dict):
    """
    Retrieves the details of a specific user from the ISE server.

    Parameters:
    - ise_ip (str): The IP address of the ISE server.
    - ise_auth (str): The ISE API authorization token.
    - user (dict): A dictionary containing the user data, including their name and id.

    Returns:
    - The JSON response from the API call.
    """
    global all_users
    try:
        api_path = f"/ers/config/internaluser/{user['id']}"
    except Exception:
        logger.debug(
            f"User Details: {json.dumps(user, indent=2, sort_keys=True)}")
        raise
    if user['name'].lower() in all_users:
        username = user['name'].lower()
        data = all_users[username]
        # If cache is fresh, return cached data
        if 'customAttributes' in data and 'timestamp' in data and data['timestamp'] > time.time() - config['ise_cache_ttl']:
            logger.info(
                f"Cisco ISE Data Cache Hit for user {user['name'].lower()} with data freshness {(time.time() - data['timestamp']):.2f}s")
            data = all_users[username]
        else:
            # If cache is stale or user details are not known, retrieve from ISE
            logger.warning(
                f"Cisco ISE Data Cache Miss for user {username}")
            if username in all_users:
                logger.debug(
                    f"User Details: {json.dumps(all_users[username], indent=2, sort_keys=True)}")
            else:
                logger.debug(
                    f"User Details for {username} not found in cache.")
            try:
                logger.debug(
                    f"Cisco ISE API: Request ISE User {username} Details, ISE {ise_ip}")
                response = ise_api_call(ise_ip, ise_auth, api_path)
            except Exception:
                logger.error(
                    f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred.")
                logger.error(
                    f"Response: {response.text}, Status Code: {response.status_code}")
            else:
                logger.info(
                    f"Cisco ISE API: User {username} Details Retrieved, ISE {ise_ip}")
            data = response.json()['InternalUser']
            data['timestamp'] = time.time()
    return data


def ise_enrich_user(ise_ip: str, ise_auth: str, username: str) -> dict:
    global all_users
    username = username.lower()
    try:
        if username in all_users:
            logger.debug(f"User {username} found in cache.")
        else:
            logger.warning(
                f"User {username} not found in cache. Fetching full list of users from ISE.")
            all_users = ise_get_all_users(ise_ip, ise_auth)
        all_users[username] = ise_get_user_details(
            ise_ip, ise_auth, all_users[username])
        # Save user data to cache
        save_user_data()
        user = all_users[username]
    except KeyError:
        logger.error(
            f"Cisco ISE API: User {username} not found on ISE {ise_ip}")
    except Exception as e:
        logger.error(
            f"Cisco ISE API: ISE {ise_ip} Unreachable or error occurred")
        time.sleep(1)
    else:
        logger.debug(
            f"User details for {username} synced with ISE Data Cache.")
        return user
    return None


def ise_update_user(ise_ip: str,
                    ise_auth: str,
                    username: str,
                    custom_attributes: dict = {}):
    """
    Updates a user on the ISE server and adds custom attributes.

    Parameters:
    - ise_ip (str): The IP address of the ISE server.
    - ise_auth (str): The ISE API authorization token.
    - username (str): The name of the user to update.
    - custom_attributes (dict): A dictionary of custom attributes to add to the user (defaults to an empty dictionary).

    Returns:
    - res: The result of the API call.
    """
    # Enrich user details (if not already done) and get user
    username = username.lower()
    u = ise_enrich_user(ise_ip, ise_auth, username)
    if u is None:
        logger.error(
            f"User {username} does not seem to exist. Aborting update")
        return False

    api_path = f"/ers/config/internaluser/{u['id']}"
    api_payload_dict = {
        "InternalUser": {
            "name": u['name'],
            "id": u["id"],
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
        except Exception:
            logger.error(
                f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred.")
            traceback.print_exc()
        else:
            all_users[u['name'].lower()]['customAttributes'] = custom_attributes
            save_user_data()
            logger.debug(
                f"Status Code: {res.status_code}, Response Body: {json.dumps(res.json(), indent=2)}")
            logger.info(
                f"User {u['name']} updated.")
            return res


def ise_get_all_devices(ise_ip: str, ise_auth: str) -> list:
    """
    Retrieves all devices from the ISE server.

    Parameters:
    - ise_ip (str): The IP address of the ISE server.
    - ise_auth (str): The ISE API authorization token.

    Returns:
    - The JSON response from the API call.
    """
    api_path = "/ers/config/networkdevice?size=100&page=1"
    continue_flag = True
    while continue_flag:
        for _ in range(3):
            try:
                logger.info(
                    f"Cisco ISE API: Request All ISE Devices, from ISE {ise_ip}")
                response = ise_api_call(ise_ip, ise_auth, api_path)
            except Exception as e:
                logger.error(
                    f"Cisco ISE API: Connection Failure, ISE {ise_ip} Unreachable or error occurred")
                logger.debug(traceback.format_exc())
                time.sleep(1)
            else:
                if response.status_code == 401:
                    logger.error(
                        "Cisco ISE API: Authentication Failure. Please check credentials")
                    logger.error(
                        f"Response: {response.text}, Status Code: {response.status_code}")
                    return []
                logger.info(
                    f"Cisco ISE API: ISE Devices Retrieved, ISE {ise_ip}")
                continue_flag = False
                break
        continue_flag = False
    return response.json()['SearchResult']['resources']


def ise_get_device_details(ise_ip: str, ise_auth: str, device: dict) -> dict:
    """
    Retrieves the details of a device from the ISE server.

    Parameters:
    - ise_ip (str): The IP address of the ISE server.
    - ise_auth (str): The ISE API authorization token.
    - device (dict): The device to retrieve details for.

    Returns:
    - The JSON response from the API call.
    """

    api_path = f"/ers/config/networkdevice/{device['id']}"
    data = ise_api_call(ise_ip, ise_auth, api_path).json()['NetworkDevice']
    return data


def ise_set_device_details(ise_ip: str, ise_auth: str, devicedata: dict) -> dict:
    """"""
    api_path = f"/ers/config/networkdevice/{devicedata['id']}"
    api_payload_dict = {"NetworkDevice": devicedata}
    res = ise_api_call(ise_ip, ise_auth, api_path, method="PUT",
                       payload=json.dumps(api_payload_dict))
    return res


all_users = load_user_data()
