#!/usr/bin/python3
import base64
import json
import requests
import time
import pickle
import os
from logger import init_logging, logger

import traceback

# Setup config
init_logging()
# Specify level = 'DEBUG' if Debug data is needed.
# init_logging(level='DEBUG')

requests.packages.urllib3.disable_warnings()

# Globally cached lists (all_users, all_groups)


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


all_users = load_user_data()


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
    return result


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
    """
    Retrieves the details of a specific user from the ISE server.

    Parameters:
    - ise_ip (str): The IP address of the ISE server.
    - ise_auth (str): The ISE API authorization token.
    - user (dict): A dictionary containing the user data, including their name and id.

    Returns:
    - The JSON response from the API call.
    """
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
        if username in all_users:
            logger.info(f"Cache Hit for user {username}")
        else:
            all_users = ise_get_all_users(ise_ip, ise_auth)
        all_users[username] = ise_get_user_details(
            ise_ip, ise_auth, all_users[username])['InternalUser']
        save_user_data()
        user = all_users[username]
    except Exception as e:
        logger.error(
            f"Cisco ISE API: ISE {ise_ip} Unreachable or error occurred")
        traceback.print_exc()
        time.sleep(1)
    else:
        logger.info(
            f"Cisco ISE API: Connection Succeeded, User details for {username} updated and synced with ISE")
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
            all_users[u['name']]['customAttributes'] = custom_attributes
            save_user_data()
            logger.debug(
                f"Status Code: {res.status_code}, Response Body: {json.dumps(res.json(), indent=2)}")
            logger.info(
                f"User {u['name']} updated.")
            return res
