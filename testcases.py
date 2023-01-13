import json
import random
import cisco_ise
import time
import sys
import re
from config import get_config
from logger import logger, init_logging

config = get_config()

ise_auth = cisco_ise.ise_auth(
    config['ise_credentials']['username'],
    config['ise_credentials']['password'])

init_logging(level='DEBUG')


def get_trailing_number(s):
    m = re.search(r'\d+$', s)
    return int(m.group()) if m else None

# A function that gets all IdentityGroups from ISE


def get_groups():
    ise_ip = config["ise_api_ip"]
    ise_auth = cisco_ise.ise_auth(
        config['ise_credentials']['username'],
        config['ise_credentials']['password'])
    ise_port = config["ise_api_port"]
    ise_path = "/ers/config/identitygroup"
    ise_method = "GET"
    ise_payload = None
    result = cisco_ise.ise_api_call(
        ise_ip=ise_ip,
        ise_auth=ise_auth,
        path=ise_path,
        method=ise_method,
        ise_port=ise_port,
        payload=ise_payload
    )
    group_data = result.json()['SearchResult']['resources']
    group_dict = {}
    for group in group_data:
        group_dict[group['name']] = group['id']
    return group_dict

# A function that creates a new user on ISE


def delete_ise_user(user_id):
    ise_ip = config["ise_api_ip"]
    ise_port = config["ise_api_port"]
    ise_path = f"/ers/config/internaluser/{user_id}"
    ise_method = "DELETE"
    global ise_auth
    ise_payload = None
    for _ in range(3):
        try:
            result = cisco_ise.ise_api_call(
                ise_ip=ise_ip,
                ise_auth=ise_auth,
                path=ise_path,
                method=ise_method,
                ise_port=ise_port,
                payload=ise_payload
            )
        except Exception as e:
            print(e)
            print("Retrying...")
            time.sleep(0.5)
            continue
        else:
            break
    return result


def create_ise_user(user_name, user_password, user_email, group_id):
    ise_ip = config["ise_api_ip"]
    ise_port = config["ise_api_port"]
    ise_path = "/ers/config/internaluser"
    ise_method = "POST"
    global ise_auth
    ise_payload = {
        "InternalUser": {
            "name": user_name,
            "password": user_password,
            "email": user_email,
            "identityGroups": f"{group_id}",
            "changePassword": "false",
            "firstName": "Test",
            "lastName": f"User {get_trailing_number(user_name)}",
        }
    }
    for _ in range(3):
        try:
            result = cisco_ise.ise_api_call(
                ise_ip=ise_ip,
                ise_auth=ise_auth,
                path=ise_path,
                method=ise_method,
                ise_port=ise_port,
                payload=json.dumps(ise_payload)
            )
        except Exception as e:
            print(e)
            print("Retrying...")
            time.sleep(0.5)
            continue
        else:
            break
    return result


if __name__ == "__main__":
    print(json.dumps(get_groups(), indent=2))
    group_data = get_groups()
    all_users = cisco_ise.ise_get_all_users(config['ise_api_ip'], ise_auth)
    if "delete" in sys.argv:
        for username in all_users:
            logger.info(f"User {username} already exists")
            logger.warning(f"Deleting user {username} for re-creation")
            delete_ise_user(all_users[username]["id"])
    else:
        for i in range(1, 5000):
            # Randomly select either 0 and 1 and assign to a variable
            groups = ['asiacell_employees', 'asiacell_external_users']
            group = groups[random.randint(0, 1)]
            group_id = group_data[group]
            if group == 'asiacell_employees':
                username = f'user{i}'
            elif group == 'asiacell_external_users':
                username = f'extuser{i}'
            res = create_ise_user(f"{username}", "Password123",
                                  f"{username}@asiacell.com", group_id)
            if res.status_code == 201:
                print(
                    f"Created user {username} - Status Code {res.status_code}")
            elif res.status_code == 500:
                print(
                    f"User {username} already exists - Status Code {res.status_code}")
