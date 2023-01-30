import asyncio
import cisco_ise
import pan_fw
import json
import datetime
import os
from config import get_config
from fastapi import Request, FastAPI
from logger import init_logging, logger

app = FastAPI(debug=False)
# Setup Logging config
init_logging()
# Setup CSV Logging


def csv_log(csv_dir="./logs"):
    csv_fname = f'{datetime.datetime.now().strftime("%Y-%m-%d.gp-dup-sessions.csv")}'
    csv_path = os.path.join(csv_dir, csv_fname)
    csv_header = "sn,username,date,time,connected-hostname,connected-os,connected-public-ip," \
                 "denied-session-hostname,denied-session-os,denied-session-public-ip\n"
    if not os.path.exists(csv_dir):
        os.makedirs(csv_dir)
    if not os.path.isfile(csv_path):
        with open(csv_path, "a+") as csv_file:
            csv_file.write(csv_header)
    return csv_path


config = get_config()
ise_token = config['ise_credentials']['token']

try:
    fw_api_key = config['fw_credentials']['api_key']
except Exception:
    fw_api_key = None

if fw_api_key is None:
    logger.error(
        "PAN-OS API Key is empty. Please ensure valid key is initialized in config (use config.py to regenerate). API Disabled.")
    exit(1)


@app.on_event('shutdown')
def shutdown_event():
    print('Shutting down...!')


async def exit_app():
    loop = asyncio.get_running_loop()
    loop.stop()


@app.get("/")
async def root():
    return {"message": "Please use the /connected and /disconnected endpoints."}


@app.post("/connected")
async def connected_event(request: Request) -> dict:
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    data = await request.json()
    logger.info(json.dumps(data, indent=2))
    if 'customAttributes' in data['InternalUser'].keys():
        res = update_user(data['InternalUser']['name'],
                          data['InternalUser']['customAttributes'])
    else:
        res = update_user(data['InternalUser']['name'], {
            'PaloAlto-GlobalProtect-Client-Version': "Unknown"})
    logger.warning(
        f"User {data['InternalUser']['name']} connected to GP. Attributes updated in ISE.")
    return res.json()


@ app.post("/disconnected")
async def disconnected_event(request: Request) -> dict:
    global config
    global fw_api_key
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    data = await request.json()
    gp_connected_user_data = pan_fw.fw_gp_ext(config['fw_ip'], fw_api_key)
    if data['InternalUser']['name'] in gp_connected_user_data.keys():
        if len(gp_connected_user_data[data['InternalUser']['name']]) > 0:
            sync_gp_session_state(config)
            logger.warning(
                f"User {data['InternalUser']['name']} updated with existing session data on ISE.")
            return {"info": f"User {data['InternalUser']['name']} updated with existing session data."}
    logger.debug(json.dumps(data, indent=2))
    if 'customAttributes' in data['InternalUser'].keys():
        res = update_user(data['InternalUser']['name'],
                          data['InternalUser']['customAttributes'])
    else:
        res = update_user(
            data['InternalUser']['name'],
            {
                "PaloAlto-Client-Hostname": "",
                "PaloAlto-Client-OS": "",
                "PaloAlto-Client-Source-IP": "",
                "PaloAlto-GlobalProtect-Client-Version": "N-A"
            })

    logger.warning(
        f"User {data['InternalUser']['name']} disconnected from GP. Attributes updated in ISE.")
    return res.json()


@app.get('/debug/getusersfromise')
async def get_users_ise(request: Request) -> dict:
    """
    Retrieve all users from ISE and cache them.

    Args:
    request (Request): The incoming request object.

    Returns:
    dict: A dictionary containing all the ISE users.

    """
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    global ise_token
    global config
    return cisco_ise.ise_get_all_users(config['ise_api_ip'], ise_token)


@app.get('/debug/getcachedusers')
async def get_users_cache(request: Request) -> dict:
    """
    Retrieve all users from cache.

    Args:
    request (Request): The incoming request object.

    Returns:
    dict: A dictionary containing all the ISE users from the cache.

    """
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    return cisco_ise.all_users


@app.get('/sync')
async def sync_request(request: Request) -> dict:
    """
    Sync the ISE users with the connected state from the firewall.

    Args:
    request (Request): The incoming request object.

    Returns:
    dict: A dictionary containing data about GP connected users from the firewall.
    """
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    global config
    return sync_gp_session_state(config)


@app.post('/syncuser/{username}')
async def sync_user_request(username: str, request: Request) -> dict:
    """
    Sync a single user with the connected state from the firewall.

    Args:
    - username (str): The username of the user to sync.
    - request (Request): The incoming request object.

    Returns:
    dict: A dictionary containing the user data after the update.
    """
    try:
        data = await request.json()
        logger.debug(f"POST Data Received: {json.dumps(data, indent=2)}")
    except Exception:
        logger.error(f"Malformed request received for /syncuser/{username}")
        return
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    global config
    global ise_token
    user = cisco_ise.ise_enrich_user(
        config['ise_api_ip'],
        ise_token,
        username
    )
    if user and '.' in user['customAttributes']['PaloAlto-GlobalProtect-Client-Version']:
        logger.info(f"User {user['name']} synced with connected state on ISE")
        gpusers = sync_gp_session_state(config)
        attributes = data['InternalUser']['customAttributes']
        if attributes != user['customAttributes']:
            logger.warning(
                f"User {user['name']} tried login with new location while already connected. New attempt parameters {attributes}")
            csvlogfile = csv_log()
            csv_entry = f'{datetime.datetime.now().strftime("%Y%m%d%H%M%S")},' \
                f'{user["name"]},' \
                f'{datetime.datetime.now().strftime("%b.%d.%Y")},' \
                f'{datetime.datetime.now().strftime("%H:%M:%S")},' \
                f'{user["customAttributes"]["PaloAlto-Client-Hostname"]},' \
                f'{user["customAttributes"]["PaloAlto-Client-OS"]},' \
                f'{user["customAttributes"]["PaloAlto-Client-Source-IP"]},' \
                f'{gpusers[user["name"]][0]["Raw-Data"]["source-region"]},' \
                f'{attributes["PaloAlto-Client-Hostname"]},' \
                f'{attributes["PaloAlto-Client-OS"]},' \
                f'{attributes["PaloAlto-Client-Source-IP"]},' \
                f'{attributes["PaloAlto-Client-Region"]}'
            with open(csvlogfile, "a+") as csv_file:
                csv_file.write(csv_entry + "\n")
    return user


def update_user(user: str, custom_attributes: dict) -> dict:
    """
    Update a user in ISE with custom attributes.

    Args:
    - user (str): The username of the user to update.
    - custom_attributes (dict): A dictionary containing the custom attributes to update.

    Returns:
    dict: A dictionary containing the user data after the update.
    """
    global ise_token
    res = cisco_ise.ise_update_user(
        config['ise_api_ip'],
        ise_token,
        user,
        custom_attributes
    )
    return res


def sync_gp_session_state(config: dict, initial: bool = False) -> dict:
    """
    A function to sync the GP connected state from the firewall with the ISE users.

    Args:
    - config (dict): A dictionary containing the configuration data.
    - initial (bool): A boolean to indicate if this is the initial sync.

    Returns:
    - dict: A dictionary containing the GP connected users from the firewall.
    """
    global ise_token
    global fw_api_key
    gp_connected_user_data = pan_fw.fw_gp_ext(config['fw_ip'], fw_api_key)
    ise_gp_connected_users = []
    for user in cisco_ise.all_users:
        if 'customAttributes' in cisco_ise.all_users[user].keys():
            if '.' in cisco_ise.all_users[user]['customAttributes']['PaloAlto-GlobalProtect-Client-Version']:
                ise_gp_connected_users.append(user)
    for user in gp_connected_user_data:
        if initial or (user not in ise_gp_connected_users):
            cache_user = cisco_ise.ise_enrich_user(
                config['ise_api_ip'],
                ise_token,
                user)
            if cache_user is None:
                logger.error(
                    'ISE user details not found. Please ensure ISE connectivity and check credentials')
                return None
            if '.' not in cache_user['customAttributes']['PaloAlto-GlobalProtect-Client-Version']:
                u_dict = gp_connected_user_data[user][0]
                custom_attributes = {
                    "PaloAlto-Client-Hostname": u_dict['Client-Hostname'],
                    "PaloAlto-Client-OS": u_dict['Client-OS'],
                    "PaloAlto-Client-Source-IP": u_dict['Client-Source-IP'],
                    "PaloAlto-GlobalProtect-Client-Version": 'X.X.X-Unknown'
                }
                try:
                    cisco_ise.ise_update_user(
                        config['ise_api_ip'],
                        ise_token,
                        u_dict['Username'],
                        custom_attributes=custom_attributes)
                except Exception:
                    logger.error(
                        f"Error updating user {u_dict['Username']} on ISE")
                    raise
                logger.warning(
                    f"Updated user {u_dict['Username']} on ISE to GP Connected state")
    for user in ise_gp_connected_users:
        if user not in gp_connected_user_data.keys():
            custom_attributes = {
                "PaloAlto-Client-Hostname": '',
                "PaloAlto-Client-OS": '',
                "PaloAlto-Client-Source-IP": '',
                "PaloAlto-GlobalProtect-Client-Version": 'N-A'
            }
            try:
                cisco_ise.ise_update_user(
                    config['ise_api_ip'],
                    ise_token,
                    user,
                    custom_attributes=custom_attributes
                )
            except Exception:
                logger.error(f"Error updating user {user} on ISE")
                raise
            else:
                logger.warning(
                    f"Updated user {user} on ISE to GP Non-connected state")
    return gp_connected_user_data


# Perform an initial sync
sync_gp_session_state(config, initial=True)
