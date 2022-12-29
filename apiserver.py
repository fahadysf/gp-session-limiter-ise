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
        res = update_user(data['InternalUser']['name'],
                          data['InternalUser']['customAttributes'])
    else:
        res = update_user(data['InternalUser']['name'], {
            'PaloAlto-GlobalProtect-Client-Version': "Unknown"})
    return res.json()


@app.post("/disconnected")
async def disconnected_event(request: Request) -> dict:
    data = await request.json()
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


def update_user(user: str, custom_attributes: dict) -> bool:
    global ise_token
    res = cisco_ise.ise_update_user(
        config['ise_api_ip'],
        ise_token,
        user,
        custom_attributes
    )
    return res
