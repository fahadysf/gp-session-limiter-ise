import os
import cisco_ise
import pan_fw
import json
import yaml
from fastapi import Request, FastAPI
from logger import init_logging, logger

app = FastAPI(debug=False)
# Setup Logging config
init_logging()


def get_config(config_file="config.yaml") -> dict:
    with open(config_file, "r") as yamlfile:
        config = yaml.load(yamlfile, Loader=yaml.FullLoader)
        logger.info(f"Read config successfully from {config_file}")
    if "FW_IP" in os.environ:
        config['fw_ip'] = os.environ["FW_IP"]
    if "FW_UNAME" in os.environ:
        config['fw_credentials']['username'] = os.environ["FW_UNAME"]
    if "FW_PWD" in os.environ:
        config['fw_credentials']['password'] = os.environ["FW_PWD"]
    if "ISE_IP" in os.environ:
        config['ise_api_ip'] = os.environ["ISE_IP"]
    if "ISE_UNAME" in os.environ:
        config['ise_credentials']['username'] = os.environ["ISE_UNAME"]
    if "ISE_PWD" in os.environ:
        config['ise_credentials']['password'] = os.environ["ISE_PWD"]
    # Update config based on env variables
    with open(config_file, 'w') as yamlfile:
        yaml.dump(config, yamlfile, default_flow_style=False)
        logger.info(
            f"Config successfully updated based on Environment Variables (Output: {config_file})")
    return config


config = get_config()
ise_token = cisco_ise.ise_auth(
    config['ise_credentials']['username'],
    config['ise_credentials']['password']
)

fw_api_key = pan_fw.fw_key(
    config['fw_ip'],
    config['fw_credentials']['username'],
    config['fw_credentials']['password']
)


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
            return {"info": f"User {data['InternalUser']['name']} updated with existing session data."}
    logger.info(json.dumps(data, indent=2))
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

    return res.json()


@app.get('/sync')
async def sync_request(request: Request) -> dict:
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    global config
    return sync_gp_session_state(config)


@app.get('/syncuser/{username}')
async def sync_user_request(username: str, request: Request) -> dict:
    logger.info(f"{request.client.host} - {request.method} - {request.url}")
    global config
    global ise_token
    user = cisco_ise.ise_enrich_user(
        config['ise_api_ip'],
        ise_token,
        username
    )
    if user and user['customAttributes']['PaloAlto-GlobalProtect-Client-Version'] != "N-A":
        logger.info(f"User {user['name']} synced with connected state on ISE")
        sync_gp_session_state(config)
    return user


def update_user(user: str, custom_attributes: dict) -> bool:
    global ise_token
    res = cisco_ise.ise_update_user(
        config['ise_api_ip'],
        ise_token,
        user,
        custom_attributes
    )
    return res


def sync_gp_session_state(config: dict, initial: bool = False) -> bool:
    global ise_token
    global fw_api_key
    gp_connected_user_data = pan_fw.fw_gp_ext(config['fw_ip'], fw_api_key)
    logger.info(f"Connected GP Users Data:\n {gp_connected_user_data}")
    ise_gp_connected_users = []
    for user in cisco_ise.all_users:
        if 'customAttributes' in cisco_ise.all_users[user].keys():
            if cisco_ise.all_users[user]['customAttributes']['PaloAlto-GlobalProtect-Client-Version'] != "N-A":
                ise_gp_connected_users.append(user)
    for user in gp_connected_user_data:
        if initial or (user not in ise_gp_connected_users):
            cache_user = cisco_ise.ise_enrich_user(
                config['ise_api_ip'],
                ise_token,
                user)
            if cache_user['customAttributes']['PaloAlto-GlobalProtect-Client-Version'] == "N-A":
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
