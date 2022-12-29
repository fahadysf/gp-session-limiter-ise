from fastapi import Request, FastAPI
from logger import init_logging, logger
import cisco_ise
import json
import yaml

app = FastAPI()
# Setup config
init_logging()


def get_config(config_file="config.yaml") -> dict:
    with open(config_file, "r") as yamlfile:
        config = yaml.load(yamlfile, Loader=yaml.FullLoader)
        logger.info(f"Read config successfully from {config_file}")
    return config


config = get_config()
ise_token = cisco_ise.ise_auth(
    config['ise_credentials']['username'],
    config['ise_credentials']['password']
)


@app.get("/")
async def root():
    return {"message": "Please use the /connected and /disconnected endpoints."}


@app.post("/connected")
async def connected_event(request: Request) -> dict:
    data = await request.json()
    logger.info(json.dumps(data, indent=2))
    if 'customAttributes' in data['InternalUser'].keys():
        add_user_to_group(data['InternalUser']['name'],
                          config['gp_users_group'],
                          data['InternalUser']['customAttributes'])
    else:
        add_user_to_group(data['InternalUser']['name'],
                          config['gp_users_group'],
                          {})
    return data


@app.post("/disconnected")
async def disconnected_event(request: Request) -> dict:
    data = await request.json()
    logger.info(json.dumps(data, indent=2))
    if 'customAttributes' in data['InternalUser'].keys():
        del_group_from_user(data['InternalUser']['name'],
                            config['gp_users_group'],
                            data['InternalUser']['customAttributes'])
    else:
        del_group_from_user(data['InternalUser']['name'],
                            config['gp_users_group'],
                            {})

    return data


def add_user_to_group(user: str, group: str, custom_attributes: dict) -> bool:
    global ise_token
    cisco_ise.ise_add_grp_to_user(
        config['ise_api_ip'],
        ise_token,
        user,
        group,
        custom_attributes
    )
    return True


def del_group_from_user(user: str, group: str, custom_attributes: dict) -> bool:
    global ise_token
    cisco_ise.ise_del_grp_from_user(
        config['ise_api_ip'],
        ise_token,
        user,
        group,
        custom_attributes
    )
    return True
