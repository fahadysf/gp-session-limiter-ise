#!/usr/bin/python3
import datetime
import os

from pan_fw import fw_key, fw_gp_ext, fw_gp_lst
from cisco_ise import ise_auth, ise_users_all, ise_user_gp, ise_del_gp_users, ise_add_gp_users,ise_grp_id

log4y = lambda _: print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S") + " " + _)
ise_gp_del = lambda fw_gp, ise_gp: list(filter(lambda _: _ not in fw_gp, ise_gp))
ise_gp_add = lambda fw_gp, ise_gp: list(filter(lambda _: _ not in ise_gp, fw_gp))

fw_ip = os.environ["FW_IP"]
fw_uname = os.environ["FW_UNAME"]
fw_pwd = os.environ["FW_PWD"]

ise_ip = os.environ["ISE_IP"]
ise_uname = os.environ["ISE_UNAME"]
ise_pwd = os.environ["ISE_PWD"]


if __name__ == '__main__':
    key = fw_key(fw_ip=fw_ip, uname=fw_uname, pwd=fw_pwd)
    if key:
        fw_gp_users_ext = fw_gp_ext(fw_ip=fw_ip, fw_key=key)
        fw_gp_users_sum = fw_gp_lst(fw_gp_users_ext)
    else:
        log4y(f"Palo Alto NGFW {fw_ip} Not Reachable")

    ise_auth_key = ise_auth(uname=ise_uname, pwd=ise_pwd)
    ise_all_users_sum = ise_users_all(ise_ip=ise_ip, ise_auth=ise_auth_key)

    ise_grp_gp_users = ise_grp_id(ise_ip=ise_ip,ise_auth=ise_auth_key,grp_name="asiacell_gp_connected_users")
    ise_gp_users_sum = ise_user_gp(ise_ip=ise_ip, ise_auth=ise_auth_key, gp_grp=ise_grp_gp_users)

    log4y(f"ISE ALL Users: {ise_all_users_sum}")
    log4y(f"ISE GP Users: {ise_gp_users_sum}")
    log4y(f"NGFW GP Users: {fw_gp_users_sum}")

    ise_del_lst = ise_gp_del(fw_gp=fw_gp_users_sum, ise_gp=ise_gp_users_sum)
    log4y(f"Members to be Deleted from Cisco ISE GP Group: {ise_del_lst}")

    ise_add_lst = ise_gp_add(fw_gp=fw_gp_users_sum, ise_gp=ise_gp_users_sum)
    log4y(f"Members to be ADDED to Cisco ISE GP Group: {ise_add_lst}")

    ise_grp_all_users = ise_grp_id(ise_ip=ise_ip, ise_auth=ise_auth_key, grp_name="asiacell_employees")
    ise_del_gp_users(ise_ip="192.0.0.31", ise_auth=ise_auth_key, all_users_grp=ise_grp_all_users,
                     gp_del_lst=ise_del_lst)
    ise_add_gp_users(ise_ip="192.0.0.31", ise_auth=ise_auth_key, gp_add_lst=ise_add_lst, gp_all_ext=fw_gp_users_ext)
