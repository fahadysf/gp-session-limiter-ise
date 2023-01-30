# Configuration Section
import json
from urllib import request, parse
ISE_IP = "192.0.0.22"
ISE_TOKEN = "Basic ZnlvdXN1ZjpGYWhhZEAxMjM="
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


def set_ise_group(ise_ip, ise_token, device_name, group_name):
    """
    This function sets the group of a device in ISE.
    """
    # Step 1: Get the device ID
    url = "https://" + ise_ip + "/ers/config/networkdevice"

    url = "https://" + ise_ip + "/ers/config/endpointgroup/name/" + group_name
    req = request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", ise_token)
    req.add_header("Connection", "keep-alive")
    req.add_header("Cache-Control", "no-cache")
    req.add_header("Host", ise_ip)
    req.add_header("User-Agent", "PostmanRuntime/7.13.0")
    req.add_header("Accept-Encoding", "gzip, deflate")
    req.add_header("Content-Length", "0")
    req.get_method = lambda: "PUT"
    response = request.urlopen(req)
    return response


if __name__ == "__main__":
    r = do_healthcheck(MIDDLEWARE_IP, MIDDLEWARE_PORT)
    if r.getcode() == 200:
        print("Middleware is healthy")
