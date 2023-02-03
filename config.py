import os
import base64
from argon2 import PasswordHasher
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
    token = base64.b64encode(f"{uname}:{pwd}".encode('utf-8')).decode("utf-8")
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


def initialize_credentials(config_file: str = "config.yaml"):
    import getpass
    config = get_config(config_file)
    print("--- GP Session Limiting Middleware Config Tool ---\n")
    print(f"Config File:\t{config_file}")
    print(f"Firewall IP:\t{config['fw_ip']}")
    print(f"ISE IP:\t\t{config['ise_api_ip']}")
    print(f"SMTP Server:\t{config['smtp_server']}\n")
    config = get_config()
    modified = False

    # Set API Username and Password
    # TODO: Add support for API Key
    flag = input(
        "Do you want to create or reset credentials for the Middleware API? (y/n)")
    while True:
        if len(flag.strip()) and (flag.strip()[0] == "y" or flag.strip() == "Y"):
            username = input("Please Enter Middleware API Username: ")
            password = getpass.getpass(
                'Please Enter Middleware API Password: ')
            saltedhash = PasswordHasher().hash(password)
            config['api_user'] = username
            config['api_password'] = saltedhash
            modified = True
            break
        elif flag.strip() == '' or flag.strip()[0] == 'n' or flag.strip() == 'N':
            print(
                "Skipping API Credentials setup. Existing user/password in config file will be used (if exists).")
            break
        else:
            flag = input("Please enter y or n: ")

    # Generate FW Api Key
    flag = input("Do you want to generate FW API Key? (y/n)")
    while True:
        if len(flag.strip()) and flag.strip()[0] == "y" or flag.strip() == "Y":
            fw_api_key = None
            while not fw_api_key:
                fw_username = input("Please Enter GP Gateway NGFW Username: ")
                fw_password = getpass.getpass(
                    "Please Enter GP Gateway NGFW Password: ")
                fw_api_key = fw_key(config['fw_ip'], fw_username, fw_password)
                if not fw_api_key:
                    print(
                        "FW API Key Not Generated. Please check connection and credentials. Try again or press Ctrl+C to exit.")
                else:
                    config['fw_credentials']['api_key'] = fw_api_key
                    if 'username' in config:
                        config['fw_credentials'].pop('username')
                    if 'password' in config:
                        config['fw_credentials'].pop('password')
                    print("FW API Key Generated Successfully.")
                    modified = True
            break
        elif flag.strip() == '' or flag.strip()[0] == "n" or flag.strip() == "N":
            print(
                "Skipping FW API Key Generation. Existing key in config (if present) will be used.")
            break
        else:
            flag = input("Please enter y or n: ")

    # Generate ISE Token
    flag = input("Do you want to generate ISE Token? (y/n)")
    while True:
        if len(flag.strip()) and flag.strip()[0] == 'y' or flag.strip() == 'Y':
            ise_username = input("Please Enter ISE Username: ")
            ise_password = getpass.getpass("Please Enter ISE Password: ")
            ise_token = ise_auth(ise_username, ise_password)
            config['ise_credentials']['token'] = ise_token
            if 'username' in config['ise_credentials']:
                config['ise_credentials'].pop('username')
            if 'password' in config['ise_credentials']:
                config['ise_credentials'].pop('password')
            print("ISE Token Generated Successfully.")
            modified = True
            break
        elif flag.strip() == '' or flag.strip()[0] == 'n' or flag.strip() == 'N':
            print(
                "Skipping ISE Token Generation. Existing token in config (if present) will be used.")
            break
        else:
            flag = input("Please enter y or n: ")

    # Set Email Sender Credentials
    flag = input("Do you want to set Email Sender Credentials? (y/n)")
    while True:
        if len(flag.strip()) and flag.strip()[0] == 'y' or flag.strip() == 'Y':
            print(
                "If your mail sender username is different from sender email please provide it separately.")
            print("e.g. Domain\\Username for username@domain.com")
            mail_from = input("Please Enter Sender Email Address: ")
            mail_user = input(
                f"Please Enter Sender Email Username (default: {mail_from}): ")
            if not mail_user:
                mail_user = mail_from
            mail_password = getpass.getpass(
                "Please Enter Sender Email Password: ")
            config['mail_from'] = mail_from
            config['mail_user'] = mail_user
            config['mail_password'] = base64.b64encode(
                mail_password.encode('utf-8')).decode("ascii")
            modified = True
            break
        elif flag.strip() == '' or flag.strip()[0] == 'n' or flag.strip() == 'N':
            print("Skipping Email Sender Credentials Setup. Existing credentials in config (if present) will be used.")
            break
        else:
            flag = input("Please enter y or n: ")

    if modified:
        try:
            save_config_yaml(config)
            os.chmod(config_file, 0o600)
        except Exception as e:
            print("Couldn't save config file. Please check permissions and try again.")
            print(str(e))
            exit(1)
        else:
            print(
                "Config file saved successfully. Please rerun the script if new credentials need to be used.")
            exit(0)


if __name__ == '__main__':
    try:
        initialize_credentials()
    except KeyboardInterrupt:
        print("\nCtrl+C pressed. Exiting...")
        exit(1)
