import asyncio
import cisco_ise
import pan_fw
import json
import datetime
import os
import secrets
from argon2 import PasswordHasher
from config import get_config
from fastapi import Request, Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from logger import init_logging, logger
import mailsender

app = FastAPI(debug=False)
# Setup Logging config
init_logging()
# Setup Security
security = HTTPBasic()

# Setup tsv Logging


def tsv_log(tsv_dir="./logs"):
    """Generats a monthly tsv file path for logging GP session state.
    Creates the file if it does not exist so it should be used with append mode.

    Args:
        tsv_dir (str, optional): Directory to save tsv files to. Defaults to "./logs".

    Returns:
        str: File path to the tsv file.
    """
    tsv_fname = f'{datetime.datetime.now().strftime("%Y-%m.gp-dup-sessions.tsv")}'
    tsv_path = os.path.join(tsv_dir, tsv_fname)
    tsv_header = "\t".join([
        "sn", "username", "date", "time",
        "connected-hostname", "connected-os", "connected-public-ip", "connected-region",
        "denied-session-hostname", "denied-session-os", "denied-session-public-ip", "denied-session-region"]) + "\n"
    if not os.path.exists(tsv_dir):
        os.makedirs(tsv_dir)
    if not os.path.isfile(tsv_path):
        with open(tsv_path, "a+") as tsv_file:
            tsv_file.write(tsv_header)
    return tsv_path


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
async def shutdown_event():
    print('Shutting down...!')


@app.on_event('startup')
async def startup_event():
    global config
    logger.info("Starting GP API Server: Performing initial sync.")
    try:
        syncresults = sync_gp_session_state(config, initial=True)
        logger.debug(f"Sync Results: {syncresults}")
    except Exception:
        exit(1)


async def exit_app():
    loop = asyncio.get_running_loop()
    loop.stop()


def check_auth(credentials: HTTPBasicCredentials = Depends(security)):
    global config
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = config['api_user'].encode("utf8")
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password = credentials.password.strip()
    hashedpass = config['api_password']
    ph = PasswordHasher()
    try:
        is_correct_password = ph.verify(hashedpass, current_password)
    except Exception as e:
        is_correct_password = False
    if not (is_correct_username and is_correct_password):
        logger.warning(
            'Auth Failed. Incorrect API username or password entered.')
        logger.debug(
            f"Username: {credentials.username} Password: {credentials.password}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect API username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return is_correct_password


@app.get("/")
async def root(auth_result: bool = Depends(check_auth)):
    return {
        "authenticated": auth_result,
        "message": "Please use the /connected and /disconnected endpoints."
    }


@app.get("/health")
async def root(request: Request) -> dict:
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    return {"message": "Health Check OK."}


@app.post("/connected")
async def connected_event(request: Request, auth_result: bool = Depends(check_auth)) -> dict:
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    try:
        data = await request.json()
        logger.debug(f"POST Data Received: {json.dumps(data, indent=2)}")
        if 'customAttributes' in data['InternalUser'].keys():
            res = update_user(data['InternalUser']['name'],
                              data['InternalUser']['customAttributes'])
        else:
            res = update_user(data['InternalUser']['name'], {
                'PaloAlto-GlobalProtect-Client-Version': "Unknown"})
        logger.warning(
            f"User {data['InternalUser']['name']} connected to GP. Attributes updated in ISE.")

    except Exception:
        logger.error(f"Malformed request received for /connected endpoint.")
        logger.debug(f"Request: {await request.body()}")
        return
    logger.debug(f"POST Data: {json.dumps(data, indent=2)}")
    try:
        return res.json()
    except AttributeError:
        return {"message": "User not found in ISE. Skipping update."}
    except Exception as e:
        return {f"message": "Unknown error occurred. Error: {e}"}


@ app.post("/disconnected")
async def disconnected_event(request: Request, auth_result: str = Depends(check_auth)) -> dict:
    global config
    global fw_api_key
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    data = await request.json()
    fw_ip = pan_fw.get_active_fw(
        config['fw_ip'], config['fw_ha_ip'], fw_api_key)
    if fw_ip is None:
        logger.error(
            "Unable to determine active PAN-OS device. Please check HA status and API key.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to determine active PAN-OS device. Please check HA status and API key.",
            headers={"WWW-Authenticate": "Basic"},
        )
    gp_connected_user_data = pan_fw.fw_gp_ext(fw_ip, fw_api_key)
    if data['InternalUser']['name'].lower() in [k.lower() for k in gp_connected_user_data.keys()]:
        if len(gp_connected_user_data[data['InternalUser']['name'].lower()]) > 0:
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
    try:
        logger.warning(
            f"User {data['InternalUser']['name']} disconnected from GP. Updating attributes in ISE.")
        return res.json()
    except AttributeError:
        return {"message": f"User {data['InternalUser']['name']} not found in ISE. Skipping update."}
    except Exception as e:
        return {f"message": "Unknown error occurred. Error: {e}"}


@ app.get('/debug/getusersfromise')
async def get_users_ise(request: Request, auth_result: str = Depends(check_auth)) -> dict:
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
    return cisco_ise.ise_get_all_users(cisco_ise.ise_get_pan_active(ise_token), ise_token)


@ app.get('/debug/getcachedusers')
async def get_users_cache(request: Request, auth_result: str = Depends(check_auth)) -> dict:
    """
    Retrieve all users from cache.

    Args:
    request (Request): The incoming request object.

    Returns:
    dict: A dictionary containing all the ISE users from the cache.

    """
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    return cisco_ise.all_users


@ app.get('/sync')
async def sync_request(request: Request, auth_result: str = Depends(check_auth)) -> dict:
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


@ app.get('/syncuser/{username}')
@ app.post('/syncuser/{username}')
async def sync_user_request(username: str, request: Request, auth_result: str = Depends(check_auth)) -> dict:
    """
    Sync a single user with the connected state from the firewall.

    Args:
    - username (str): The username of the user to sync.
    - request (Request): The incoming request object.

    Returns:
    dict: A dictionary containing the user data after the update.
    """
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    if not auth_result:
        logger.warning(
            f"Authentication Failed for /syncuser/{username} endpoint.")
        return {"message": "Authentication Failed."}
    try:
        data = await request.json()
        logger.debug(f"POST Data Received: {json.dumps(data, indent=2)}")
    except Exception:
        logger.error(f"Malformed request received for /syncuser/{username}")
        logger.debug(f"Request: {await request.body()}")
        return
    global config
    global ise_token
    global fw_api_key
    fw_ip = pan_fw.get_active_fw(
        config['fw_ip'], config['fw_ha_ip'], fw_api_key)
    if fw_ip is None:
        logger.error(
            "No active and reachable firewall found. Check firewall connectivity, HA status and API key.")
    user = cisco_ise.ise_enrich_user(
        cisco_ise.ise_get_pan_active(ise_token),
        ise_token,
        username.lower()
    )
    if user and '.' in user['customAttributes']['PaloAlto-GlobalProtect-Client-Version']:
        logger.info(f"User {user['name']} synced with connected state on ISE")
        gpusers = pan_fw.fw_gp_ext(fw_ip, fw_api_key, ignore_cache=True)
        attributes = data['InternalUser']['customAttributes']
        duplicate_session = \
            attributes['PaloAlto-Client-Hostname'].lower().strip(
            ) != user['customAttributes']['PaloAlto-Client-Hostname'].lower().strip() #and \
            #attributes['PaloAlto-Client-OS'].strip(
            #) != user['customAttributes']['PaloAlto-Client-OS'].strip()
        if duplicate_session and user['name'].lower() in [k.lower() for k in gpusers.keys()]:
            logger.warning(
                f"User {user['name']} tried login with new location while already connected. New attempt parameters {attributes}")
            tsvlogfile = tsv_log()
            eventdate = datetime.datetime.now().strftime("%b.%d.%Y")
            eventtime = datetime.datetime.now().strftime("%H:%M:%S")
            oldsession = user['customAttributes']
            oldsession['PaloAlto-Client-Region'] = gpusers[user['name'].lower()
                                                           ][0]['Raw-Data']['source-region']
            """
            tsv_header = "\t".join([
            "sn", "username", "date", "time",
            "connected-hostname", "connected-os", "connected-public-ip", "connected-region",
            "denied-session-hostname", "denied-session-os", "denied-session-public-ip", "denied-session-region"]) + "\n"
            """
            tsv_entry = "\t".join([
                datetime.datetime.now().strftime("%Y%m%d%H%M%S"),
                user["name"].lower(),
                eventdate,
                eventtime,
                oldsession["PaloAlto-Client-Hostname"],
                oldsession["PaloAlto-Client-OS"],
                oldsession["PaloAlto-Client-Source-IP"],
                oldsession["PaloAlto-Client-Region"],
                attributes["PaloAlto-Client-Hostname"],
                attributes["PaloAlto-Client-OS"],
                attributes["PaloAlto-Client-Source-IP"],
                attributes["PaloAlto-Client-Region"],
            ])

            if config['email_enabled']:
                mailsender.send_mail(
                    config['smtp_server'],
                    config['mail_user'],
                    config['mail_from'],
                    config['mail_to'],
                    config['mail_password'],
                    config['smtp_port'],
                    f"GP Duplicate Loging Attempt - User: {user['name'].lower()}",
                    mailsender.mail_html_body({
                        'username': user['name'].lower(),
                        'date': eventdate,
                        'time': eventtime,
                        'oldsession': user['customAttributes'],
                        'newsession': attributes
                    }),
                    mail_srv_typ=config['smtp_type']
                )
            with open(tsvlogfile, "a+") as tsv_file:
                tsv_file.write(tsv_entry + "\n")
        else:
            custom_attributes = {
                "PaloAlto-Client-Hostname": '',
                "PaloAlto-Client-OS": '',
                "PaloAlto-Client-Source-IP": '',
                "PaloAlto-GlobalProtect-Client-Version": 'N-A'
            }
            try:
                cisco_ise.ise_update_user(
                    cisco_ise.ise_get_pan_active(ise_token),
                    ise_token,
                    user['name'].lower(),
                    custom_attributes=custom_attributes
                )
            except Exception:
                logger.error(f"Error updating user {user['name']} on ISE")
                raise
            else:
                logger.warning(
                    f"Updated user {user['name']} on ISE to GP Non-connected state")
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
        cisco_ise.ise_get_pan_active(ise_token),
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
    fw_ip = pan_fw.get_active_fw(
        config['fw_ip'], config['fw_ha_ip'], fw_api_key)
    if fw_ip is None:
        logger.error(
            "No active firewall found. Check firewall HA status and API key.")
        raise Exception("No active and reachable firewall found.")
    gp_connected_user_data = pan_fw.fw_gp_ext(
        fw_ip, fw_api_key, ignore_cache=initial)
    ise_gp_connected_users = []
    for user in cisco_ise.all_users:
        if 'customAttributes' in cisco_ise.all_users[user.lower()].keys():
            if '.' in cisco_ise.all_users[user.lower()]['customAttributes']['PaloAlto-GlobalProtect-Client-Version']:
                ise_gp_connected_users.append(user.lower())
    for user in [u.lower() for u in gp_connected_user_data]:
        u_dict = gp_connected_user_data[user.lower()][0]
        if initial or (user.lower() not in ise_gp_connected_users):
            cache_user = cisco_ise.ise_enrich_user(
                cisco_ise.ise_get_pan_active(ise_token),
                ise_token,
                user.lower())
            if cache_user is None:
                logger.error(
                    'ISE user details not found. Please ensure ISE connectivity and check credentials')
            elif '.' not in cache_user['customAttributes']['PaloAlto-GlobalProtect-Client-Version']:
                custom_attributes = {
                    "PaloAlto-Client-Hostname": u_dict['Client-Hostname'],
                    "PaloAlto-Client-OS": u_dict['Client-OS'],
                    "PaloAlto-Client-Source-IP": u_dict['Client-Source-IP'],
                    "PaloAlto-GlobalProtect-Client-Version": 'X.X.X-Unknown'
                }
                try:
                    cisco_ise.ise_update_user(
                        cisco_ise.ise_get_pan_active(ise_token),
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
                    cisco_ise.ise_get_pan_active(ise_token),
                    ise_token,
                    user,
                    custom_attributes=custom_attributes
                )
            except Exception:
                logger.error(f"Error updating user {user} on ISE")
            else:
                logger.warning(
                    f"Updated user {user} on ISE to GP Non-connected state")
        else:
            u_dict = gp_connected_user_data[user][0]
            cache_user = cisco_ise.all_users[user]
            if cache_user is None:
                logger.warning(
                    f"User {user} not found in ISE Users. Skipping update of attributes.")
            elif u_dict['Client-Hostname'] != cache_user['customAttributes']['PaloAlto-Client-Hostname'] \
                    or u_dict['Client-OS'] != cache_user['customAttributes']['PaloAlto-Client-OS'] \
                    or u_dict['Client-Source-IP'] != cache_user['customAttributes']['PaloAlto-Client-Source-IP']:
                custom_attributes = {
                    "PaloAlto-Client-Hostname": u_dict['Client-Hostname'],
                    "PaloAlto-Client-OS": u_dict['Client-OS'],
                    "PaloAlto-Client-Source-IP": u_dict['Client-Source-IP'],
                    "PaloAlto-GlobalProtect-Client-Version": cache_user['customAttributes']['PaloAlto-GlobalProtect-Client-Version']
                }
                try:
                    cisco_ise.ise_update_user(
                        cisco_ise.ise_get_pan_active(ise_token),
                        ise_token,
                        u_dict['Username'],
                        custom_attributes=custom_attributes)
                except Exception:
                    logger.error(
                        f"Error updating user {u_dict['Username']} on ISE")
                    raise
                logger.warning(
                    f"Updated user {u_dict['Username']} on ISE to GP Connected state with existing session details.")
    return gp_connected_user_data
