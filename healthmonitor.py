# Configuration Section
import json
import ssl
from urllib import request
import paramiko
import time

# Disable SSL Verification
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

ISE_IP = "192.0.0.22"
ISE_TOKEN = "Basic ZnlvdXN1ZjpGYWhhZEAxMjM="
ISE_API_PORT = "9060"
FW_IP1 = "192.0.0.33"
FW_IP2 = "192.0.0.34"
FW_USER = "fw_username"
FW_PASS = "--FW--PASS--HEERE--"
FW_HEALTHCHECK_PROFILE = "gptool-health-check"
MIDDLEWARE_IP = "192.0.0.30"
MIDDLEWARE_PORT = "8000"
FW_DEVICE_NAMES = ["PAN-NGFW-VM-33"]
ENFORCING_GROUP = "Device Type#All Device Types#PAN-NGFW-DevType"
NON_ENFORCING_GROUP = "Device Type#All Device Types#PAN-NGFW-DevType#PAN-NGFW-Multi-GP-Allowed"


def do_healthcheck(middleware_ip, middleware_port):
    """
    This function checks the health of the middleware.
    """
    url = "http://" + middleware_ip + ":" + middleware_port + "/health"
    req = request.urlopen(url)
    return req


def get_req(url: str, method: str = "GET") -> request.Request:
    req = request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", ISE_TOKEN)
    req.add_header("Connection", "keep-alive")
    req.add_header("Cache-Control", "no-cache")
    req.add_header("Host", ISE_IP)
    req.add_header("User-Agent", "PostmanRuntime/7.13.0")
    req.add_header("Accept-Encoding", "utf-8")
    req.add_header("Content-Length", "0")
    req.get_method = lambda: method.upper()

    return req


def set_ise_group(ise_ip, ise_api_port, device_name, group_name):
    """
    This function sets the group of a device in ISE.
    """
    # Step 1: Get the device IDs
    url = "https://" + ise_ip + ":" + ise_api_port + "/ers/config/networkdevice/"
    req = get_req(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        response = request.urlopen(req, context=ctx)
    except Exception as e:
        print(e)
        return
    # Step 2: Find the ID of our device
    try:
        results = json.loads(response.read())
        devices = results["SearchResult"]["resources"]
        for d in devices:
            if d["name"] == device_name:
                device_id = d["id"]
                break
    except Exception as e:
        print(e)
        return
    # Step 3: Get the device details
    url = "https://" + ise_ip + ":" + ise_api_port + \
        "/ers/config/networkdevice/" + device_id
    req = get_req(url, method="GET")
    try:
        response = request.urlopen(req, context=ctx)
        device_data = json.loads(response.read())
    except Exception as e:
        print(e)
        return
    # Step 4: Set the group
    url = "https://" + ise_ip + ":" + ise_api_port + \
        "/ers/config/networkdevice/" + device_id
    req = get_req(url, method="PUT")
    ngroups = device_data['NetworkDevice']['NetworkDeviceGroupList']
    for e in ngroups:
        if e.startswith('Device Type'):
            index = ngroups.index(e)
    if ngroups[index] != group_name:
        ngroups[index] = group_name
        device_data['NetworkDevice']['NetworkDeviceGroupList'] = ngroups
        data = json.dumps(device_data).encode('utf-8')
        try:
            response = request.urlopen(req, data, context=ctx)
        except Exception as e:
            print(e)
            return
        print(f"Device {device_name} DeviceType set to {group_name}")
        return response.read()
    else:
        return None


def check_status_fw_ssh(fw_ip, fw_user, fw_pass, profile):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(FW_IP1, 22, FW_USER, FW_PASS)
        remote_conn = ssh.invoke_shell()
        out = ""
        while '>' not in out:
            while not remote_conn.recv_ready():
                time.sleep(0.1)
            out += remote_conn.recv(1000).decode("ascii")
        remote_conn.send(
            f"test http-profile name {profile} type globalprotect \n\n")
        out = ""
        while not (('failed' in out.lower()) or ('success' in out.lower())):
            while not remote_conn.recv_ready():
                time.sleep(0.1)
            out += remote_conn.recv(10000).decode("ascii")
        out = "".join([s for s in out.splitlines(True) if (
            'success' in s.lower() or 'fail' in s.lower())])
        print(f"{out}")
        if "success" in out.lower():
            failure_level = 0
            print("FW Reachability to middleware: Success")
        elif "failed" in out.lower():
            print("FW Reachability to middleware: Failure.")
            failure_level = 1
        ssh.close()
        return failure_level
    except Exception as e:
        raise


if __name__ == "__main__":
    try:
        r = do_healthcheck(MIDDLEWARE_IP, MIDDLEWARE_PORT)
    except Exception as e:
        r = None
    failure_level = 0
    if r is not None and r.getcode() == 200:
        failure_level = 0
        print("Direct Middleware Healthcheck: Success")
    else:
        failure_level = 1

    # Do Firewall to Middleware Healthcheck if MW is up
    if failure_level == 0:
        try:
            failure_level = check_status_fw_ssh(
                FW_IP1, FW_USER, FW_PASS, FW_HEALTHCHECK_PROFILE)
        except Exception:
            try:
                failure_level = check_status_fw_ssh(
                    FW_IP2, FW_USER, FW_PASS, FW_HEALTHCHECK_PROFILE)
            except Exception:
                failure_level = 1

    if failure_level == 0:
        print("Middleware is healthy. GP Session enforcement enabled.")
        for device_name in FW_DEVICE_NAMES:
            try:
                set_ise_group(ISE_IP, ISE_API_PORT,
                              device_name, ENFORCING_GROUP)
            except Exception:
                failure_level = 2
    elif failure_level == 1:
        print("Middleware is not healthy. GP Session enforcement disabled.")
        for device_name in FW_DEVICE_NAMES:
            try:
                set_ise_group(ISE_IP, ISE_API_PORT,
                              device_name, NON_ENFORCING_GROUP)
            except Exception:
                failure_level = 2

    if failure_level == 2:
        print("Failed to set device group in ISE. ISE may not be reachable.")
        for device_name in FW_DEVICE_NAMES:
            print(
                f"Please change the device group manually in ISE to {NON_ENFORCING_GROUP} for {device_name}")
