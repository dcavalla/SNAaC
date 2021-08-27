#!/usr/bin/env python

"""
This script is part of a wizard based first configuration aid for Secure Network Analytics.
For more information on this API, please visit:
https://developer.cisco.com/docs/stealthwatch/
 -
Please see README for dependencies, requirements, installation and usage.

Copyright (c) 2021, Cisco Systems, Inc. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import util
import argparse

#0.1 Try to deploy the Infrastructure SMC - FC

def collect_hg_config():
    print("")
    print("Searching for new network settings ...")

    print("")
    print("Searching for public ip and asn ...")
    #retrieve public IP
    ip, asn = util.get_public_ip_and_asn()
    print("Public ip: {} ".format(ip))
    print("ASN ip: {}".format(asn))
    hgs_config = [
        {"hg_name": "[Inside Hosts]/Catch All", "hg_id": "65534" ,"cidr":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fc00::/7", asn]},
    ]
    print("")
    #retrive trusted IP subnet and Broadcast from nic settings
    print("Searching for trusted ip and subnet ...")
    trusted_ip, subnet, broadcast = util.get_trusted_ip_and_subnet()
                            
    if trusted_ip:
        print("Trusted ip: {}".format(trusted_ip))
        print("Subnet: {}".format(subnet))
        print("Broadcast ip: {}".format(broadcast))
        
        broadcast_hg = {"hg_name": "[Inside Hosts]/By Function/Other/Broadcast",  "hg_id": "18", "cidr":[broadcast]}
        trusted_ip = {"hg_name": "[Inside Hosts]/By Function/Client IP Ranges (DHCP Range)/Trusted Users",  "hg_id": "50076", "cidr":[trusted_ip,subnet]}
        hgs_config.append(trusted_ip)
        hgs_config.append(broadcast_hg)
    else:
        print("")
        print("No trusted ip has been found, potentially you are running behind a VPN!")


    #Host Machine has to be in LAN, not VPN.
    print("")
    print("Searching for DNS ...")
    dns_ips = util.get_dns() 
    print("DNS ip {}".format(dns_ips))
    dns_hg = {"hg_name": "[Inside Hosts]/By Function/Internet Services/DNS Servers", "hg_id": "27", "cidr":dns_ips}
    hgs_config.append(dns_hg)
    natgateway_ips = ["100.64.0.0/10", ip]

    if util.is_host_on_vpn():
        print("")
        print("This wizard is running under VPN, please provide Default Gateway and DHCP IP:")
        yn = util.yn_input("Do you want to provide Default Gateway and DHCP IP ")
        dhcp_ips = []
        if yn:
            default_gw, dhcp_ip = util.get_vpn_manual_settings()
            dhcp_ips.append(dhcp_ip)
            natgateway_ips.append(default_gw)
    else:
        print("")
        print("Searching for DHCP ...")
        dhcp_ips = util.get_dhcp() 



    print("DHCP ip: {}".format(dhcp_ips))
    dhcp_hg = {"hg_name": "[Inside Hosts]/By Function/Servers/DHCP Servers", "hg_id": "36", "cidr": dhcp_ips}
    natgateway_hg = {"hg_name": "[Inside Hosts]/By Function/NAT Gateway",  "hg_id": "51",  "cidr": natgateway_ips}

    hgs_config.append(dhcp_hg)
    hgs_config.append(natgateway_hg)
    
    return hgs_config    



def main():
    util.print_welcome_banner()
    config = {}
    print("This wizard will only work with Secure Network Analytics version 7.3+.")
    yn = util.yn_input("Please confirm the SMC and the FC have been already fully deployed and that the configuration wizard (AST) has been completed:")
    if not yn:
        return False

    if not util.has_internet_connectivity():
        print("This wizard require internet connectivity, please check your internet connection and restart")
        return False

    config["smc"], smc_pw = util.get_smc_config()

    # config = util.load_config()
    if util.config_exists():
        print("")
        print("Configuration file already exists, do you want to apply this or search for new values? ")
        yn = util.yn_input("Apply")
        if yn:
            config = util.load_config()
            hgs_config = config["hostgroups"]
        else:                    
            util.delete_config()
            hgs_config = collect_hg_config()
    else:
        hgs_config = collect_hg_config()

    config["hostgroups"] = hgs_config 
    util.store_config(config)
    print("")
    print("Apply the following host group configuration to the SMC {}".format(config["smc"]["smc_ip"]))
    print("")
    util.pretty_print_hgs(config["hostgroups"])
    print("")
    yn = util.yn_input("Apply")
    if yn:
        print("")
        print("Applying hostgroups configuration to SMC {} ...".format(config["smc"]["smc_ip"]))
        hgs_config = config["hostgroups"]
        hgs_config_pushed = util.push_hgs(config["smc"], smc_pw, hgs_config)
        print("")
        if len(hgs_config_pushed)>0:
            print("New Host Group configuration have been successfully applied")
        else:
            print('For some reason no HGs have been updated')
    else:
        print("Configuration not applied, exit wizard.")
        return False


    pass




if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    # parser.add_argument('--debug', nargs='?',  action="store_true")
    parser.add_argument('-d', '--debug', help='Enable Debug output', action='store_true')
    args = parser.parse_args()
    
    util.DEBUG=args.debug
    
    main()
    print("")
    pass