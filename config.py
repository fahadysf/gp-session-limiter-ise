import os
import yaml
from logger import init_logging, logger


def get_config(config_file="config.yaml") -> dict:
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
        with open(config_file, 'w') as yamlfile:
            yaml.dump(config, yamlfile, default_flow_style=False)
            logger.info(
                f"Config successfully updated based on Environment Variables (Output: {config_file})")
    return config
