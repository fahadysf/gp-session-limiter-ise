import os
import base64
import requests
import time
import yaml
import xmltodict
from logger import init_logging, logger

requests.packages.urllib3.disable_warnings()
init_logging(level="WARNING")


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
            try:
                key = xmltodict.parse(response.text)[
                    "response"]["result"]["key"]
            except Exception:
                logger.error(
                    "FW API Key Not Generated. Please check connection and credentials.")
                return None
            return key
    return None


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


def get_config(config_file: str = "config.yaml") -> dict:
    with open(config_file, "r") as yamlfile:
        orig_config = yaml.load(yamlfile, Loader=yaml.FullLoader)
        logger.info(f"Read config successfully from {config_file}")
    config = orig_config
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
    if orig_config != config:
        save_config_yaml(config)
    return config


def save_config_yaml(config_dict: dict, config_file: str = "config.yaml"):
    try:
        with open(config_file, 'w') as yamlfile:
            yaml.dump(config_dict, yamlfile, default_flow_style=False)
            logger.info(
                f"Config successfully updated based on Environment Variables (Output: {config_file})")
    except IOError:
        logger.error("Error writing config file")
    except Exception:
        raise


def initialize_credentials():
    import getpass
    print("--- GP Session Limiting Middleware ---")
    print(f"")
    config = get_config()
    # Generate FW Api Key
    fw_api_key = None
    while not fw_api_key:
        fw_username = input("Please Enter GP Gateway NGFW Username: ")
        fw_password = getpass.getpass(
            "Please Enter GP Gateway NGFW Password: ")
        fw_api_key = fw_key(config['fw_ip'], fw_username, fw_password)
        if not fw_api_key:
            print("FW API Key Not Generated. Please check connection and credentials. Try again or press Ctrl+C to exit.")

    config['fw_credentials']['api_key'] = fw_api_key
    if 'username' in config:
        config['fw_credentials'].pop('username')
    if 'password' in config:
        config['fw_credentials'].pop('password')
    print("FW API Key Generated Successfully.")

    ise_username = input("Please Enter ISE Username: ")
    ise_password = getpass.getpass("Please Enter ISE Password: ")

    ise_token = ise_auth(ise_username, ise_password)
    config['ise_credentials']['token'] = ise_token
    if 'username' in config['ise_credentials']:
        config['ise_credentials'].pop('username')
    if 'password' in config['ise_credentials']:
        config['ise_credentials'].pop('password')

    print("ISE Token Generated Successfully.")
    try:
        save_config_yaml(config)
    except Exception:
        print("Couldn't save config file. Please check permissions and try again.")
        exit(1)
    else:
        print("Config file saved successfully. Please rerun the script if new credentials need to be used.")
        exit(0)


if __name__ == '__main__':
    initialize_credentials()
