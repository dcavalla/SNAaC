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
import os
import requests
import ipaddress
from getpass import getpass
import json
import ipwhois

#------------
import sys
from sys import platform
import dns, dns.resolver
import urllib3


DEBUG = False
CONFIG_FILE_PATH = "snaac_config.json"

try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass



def config_exists():
    return os.path.exists(CONFIG_FILE_PATH)

def delete_config():
    if config_exists():
        os.remove(CONFIG_FILE_PATH)
    pass

def load_config():    
    if not os.path.exists(CONFIG_FILE_PATH):
        return {}
    else:        
        config_file = open(CONFIG_FILE_PATH,'r')
        config = json.load(config_file)
        return config

def yn_input(msg):
    yn = input("{} y/n? ".format(msg))
    return yn.lower() == "y"
         
def get_vpn_manual_settings():
    default_gw = input("Default GW: ")
    while (not validate_ipaddress(default_gw)):
        print("Default GW IP is not a valid IP, please try again")
        default_gw = input("Default GW: ")

    dhcp_ip = input("DHCP IP: ")
    while (not validate_ipaddress(dhcp_ip)):
        print("DHCP IP is not a valid IP, please try again")
        dhcp_ip = input("DHCP IP: ")

    return default_gw, dhcp_ip


def get_smc_config():
    print("")
    smc_ip = input("SMC IP: ")
    while (not validate_ipaddress(smc_ip)):
        print("SMC IP is not a valid IP, please try again")
        smc_ip = input("SMC IP: ")

    try:
        print("")
        print("Checking SMC {} is reachable ...".format(smc_ip))
        request = requests.get("https://{}".format(smc_ip), verify=False)        
        print("SMC {} connection OK!".format(smc_ip))
    except requests.exceptions.RequestException as e:
        if DEBUG:
            print(request)
        print("SMC {} is not reachable, please check your connectivity with the SMC".format(smc_ip))
        sys.exit(1)

    print("")
    smc_username = input("SMC username: ")    
    smc_pw = getpass("SMC pw: ")
    smc_pw_repeat = getpass("SMC pw repeat: ")
    
    while (smc_pw != smc_pw_repeat):
        print("Password is not matching, try again")
        smc_pw = getpass("SMC pw: ")
        smc_pw_repeat = getpass("SMC pw repeat: ")

    #Check user is valid
    print("")
    print("Checking whether account {} is valid ...".format(smc_username))
    api_session = check_user_smc(smc_ip, smc_username, smc_pw)
    if not api_session:
        print("Account {} not valid".format(smc_username))
        sys.exit(1)
    else:
        print("Account {} is valid".format(smc_username))

    domain_id = get_domain_id(smc_ip, smc_username, smc_pw)

    if domain_id:
        print("Domain ID {} collected from the SMC".format(domain_id))
        yn = yn_input("Would you like to use this {} ".format(domain_id))
        if not yn:
            smc_domain_id = input("SMC DOMAIN_ID: ")    
            while not smc_domain_id.isnumeric():
                print("SMC DOMAIN ID is not valid, please try again")
                smc_domain_id = input("SMC DOMAIN_ID: ")    
        else:
            smc_domain_id = domain_id

    smc_config = {
        "smc_ip": smc_ip,
        "smc_username": smc_username,
        "smc_domain_id": smc_domain_id
    }

    return smc_config, smc_pw

def pretty_print_hgs(config_hgs):    
    for hg in config_hgs:
        print(hg["hg_id"], hg["hg_name"],hg["cidr"])

def push_hgs(smc_config, smc_pw, config_hgs):
    hgs_config_pushed = []
    XSRF_HEADER_NAME = 'X-XSRF-TOKEN'
    url = "https://" + smc_config["smc_ip"]  + "/token/v2/authenticate"
    login_request_data = {"username": smc_config["smc_username"], "password": smc_pw}
    api_session = requests.Session()
    response = api_session.request("POST", url, verify=False, data=login_request_data)

    if(response.status_code == 200):
        for cookie in response.cookies:
            if cookie.name == 'XSRF-TOKEN':
                api_session.headers.update({XSRF_HEADER_NAME: cookie.value})
                break

        for hg in config_hgs:
            url = 'https://' + smc_config["smc_ip"] + '/smc-configuration/rest/v1/tenants/' + str(smc_config["smc_domain_id"]) + '/tags/' + str(hg["hg_id"])
            response = api_session.request("GET", url, verify=False)
            json_response = json.loads(response.content)

            if "errors" in json_response:
                print("Host Group id:{} name: {} not found".format(hg["hg_id"],hg["hg_name"]))
                print(json_response)
                continue 

            if "data" not in json_response:
                print("Host Group returned not valid data {}".format(json_response))
                continue

            tag_details = json_response["data"]

            ranges_count_pre = len(tag_details['ranges'])

            # Modify the details of thee given tag (host group) from the SMC
            for ip in hg["cidr"]:
                if ip not in tag_details['ranges']:
                    tag_details['ranges'].append(ip)

            ranges_count_post = len(tag_details['ranges'])

            if ranges_count_post <= ranges_count_pre:
                print("Host Group has not been modified {}: {}".format(hg["hg_id"],hg["hg_name"]))
                continue

            # Update the details of thee given tag (host group) in the SMC
            request_headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
            response = api_session.request("PUT", url, verify=False, data=json.dumps(tag_details), headers=request_headers)

            # If successfully able to update the tag (host group)
            # if (response.status_code == 200) and hg["cidr"] in json.loads(response.content)["data"]["ranges"]
            if response.status_code == 200:
                print("New IP successfully added to this tag (host group) {}: {}".format(hg["hg_id"],hg["cidr"]))
                hgs_config_pushed.append(hg["hg_id"])
            # If unable to update the IPs for a given tag (host group)
            else:
                print("An error has ocurred, while updating tags (host groups) {}, with the following code {}: {}".format(hg["hg_id"], response.status_code, response.text))

        uri = 'https://' + smc_config["smc_ip"]  + '/token'
        response = api_session.delete(uri, timeout=30, verify=False)
        api_session.headers.update({XSRF_HEADER_NAME: None})

    # If the login was unsuccessful
    else:
            print("An error has ocurred, while logging in, with the following code {}".format(response.status_code))




    return hgs_config_pushed

def get_public_ip_and_asn():    
    response = requests.get('https://diagnostic.opendns.com/myip')
    if response.status_code == 200:
        ip = response.text
    else:
        return False, False

    if len(ip) > 0:
        try:
            ipaddress.ip_address(ip)
        except:
            print("IP is not an IP: ", ip)            
        else:
            y = ipwhois.IPWhois(ipaddress.ip_address(ip))
            z = y.lookup_whois()
    else:
        print("No connectivity")        
        return False, False

    asn = None
    if len(z["asn_cidr"]) > 0:
        asn = z["asn_cidr"]
    else:
        print("No asn")

    return ip, asn

def get_dns():
    dns_ips = []
    if platform == "darwin":        
        r = dns.resolver.Resolver()        
        for dns_ip in r.nameservers:
            dns_ips.append(dns_ip)

    elif platform == "win32":
        # Windows...
        if DEBUG:
            print("Win")
        import wmi
        c = wmi.WMI()
        nicConfig = c.Win32_NetworkAdapterConfiguration(IPEnabled = 1)

        for nic in nicConfig:
            if nic.DHCPServer and nic.DefaultIPGateway :
                for ip in nic.DNSServerSearchOrder:
                    dns_ips.append(ip)
            elif "0.0.0.0" in nic.DefaultIPGateway and "255.255.255.255" in nic.IPSubnet:
                for ip in nic.DNSServerSearchOrder:
                    dns_ips.append(ip)

            if len(dns_ips)>0:
                break
            

    return dns_ips

def get_dhcp():
    dhcp_ips = []
    if platform == "darwin":        
        #OS X
        pass
    
    elif platform == "win32":
        # Windows...
        if DEBUG:
            print("Win")
        import wmi
        c = wmi.WMI()
        nicConfig = c.Win32_NetworkAdapterConfiguration(IPEnabled = 1)

        for nic in nicConfig:            
            if nic.DHCPServer and nic.DefaultIPGateway:
                dhcp_ips.append(nic.DHCPServer)


    return dhcp_ips

def get_trusted_ip_and_subnet():
    trusted_ip= None
    trusted_subnet = None
    broadcast = None

    if platform == "darwin":
        import netifaces
        g = netifaces.gateways()
        if DEBUG:
            print("########")
            print(g['default'][netifaces.AF_INET])
            print("########")
        default_gateway = g['default'][netifaces.AF_INET][0]
        if_name_gateway = g['default'][netifaces.AF_INET][1]

        # OS X
        if_list = netifaces.interfaces()
        for if_name in if_list:
            #addr, subnet, broadcast(BROADCAST) from gateway            
            if if_name_gateway == if_name:
                a = netifaces.ifaddresses(if_name)
                if "broadcast" not in a[netifaces.AF_INET][0]:
                    print("Warning, not valid gateway has been found.")                    
                else:
                    if DEBUG:
                        print(a[netifaces.AF_INET][0])
                    trusted_ip = a[netifaces.AF_INET][0]["addr"]
                    netmask = a[netifaces.AF_INET][0]["netmask"]
                    broadcast = a[netifaces.AF_INET][0]["broadcast"]
                    
                    #check ipv4 or ipv6
                    if ipaddress.IPv4Address(trusted_ip):
                        trusted_subnet = ipaddress.IPv4Interface(trusted_ip+"/"+netmask)
                    elif ipaddress.IPv6Address(trusted_ip):
                        trusted_subnet = ipaddress.IPv6Interface(trusted_ip+"/"+netmask)
                break

    elif platform == "win32":
        # Windows...
        if DEBUG:
            print("Win")
        import wmi
        c = wmi.WMI()
        nicConfig = c.Win32_NetworkAdapterConfiguration(IPEnabled = 1)

        for nic in nicConfig:
            print("IPs: ")
            print(nic.IPAddress)
            print("DNS Servers:")
            print(nic.DNSServerSearchOrder)        
            print("Default GW: ")
            print(nic.DefaultIPGateway)
            print("DHCP Server: ")
            print(nic.DHCPServer)
            print(nic)		
            if nic.DefaultIPGateway:
                trusted_ip  = nic.IPAddress[0]
                mask = nic.IPSubnet[0]
                default_gateway = nic.DefaultIPGateway
	
                if ipaddress.IPv4Address(trusted_ip):
                    trusted_subnet = ipaddress.IPv4Interface(trusted_ip+"/"+mask)
                    broadcast = ipaddress.IPv4Interface(trusted_ip+"/"+mask).network.broadcast_address
                elif ipaddress.IPv6Address(trusted_ip):
                    trusted_subnet = ipaddress.IPv6Interface(trusted_ip+"/"+mask)
                    broadcast = ipaddress.IPv6Interface(trusted_ip+"/"+mask).network.broadcast_address
				
                break	

    return trusted_ip, format(trusted_subnet), format(broadcast)

def has_internet_connectivity():
    try:
        request = requests.get("https://google.com", timeout=30)
        return True
    except (requests.ConnectionError, requests.Timeout) as exception:
        return False

def store_config(config):
    with open(CONFIG_FILE_PATH, 'w') as fp:
        json.dump(config, fp, sort_keys=True, indent=4)

def validate_ipaddress(ip):
    try:
        ipaddress.ip_address(ip)        
        return True
    except:
        return False
    
def print_welcome_banner():
    print("")
    print("#############################################")
    print("#   Welcome to SNA configuration wizard     #")
    print("#   This wizard has been tested on 7.3.x    #")
    print("#   and 7.4.x of Secure Network Analytics   #")
    print("#############################################")
    print("")

def check_user_smc(smc_ip, smc_username, smc_password):        
    XSRF_HEADER_NAME = 'X-XSRF-TOKEN'
    url = "https://" + smc_ip + "/token/v2/authenticate"
    login_request_data = {"username": smc_username,"password": smc_password}
    api_session = requests.Session()
    response = api_session.request("POST", url, verify=False, data=login_request_data)

    if(response.status_code == 200):
        for cookie in response.cookies:
            if cookie.name == 'XSRF-TOKEN':
                api_session.headers.update({XSRF_HEADER_NAME: cookie.value})
                break
        
        #logout
        uri = 'https://' + smc_ip + '/token'
        response = api_session.delete(uri, timeout=30, verify=False)
        api_session.headers.update({XSRF_HEADER_NAME: None})
        return True
    else:
        return False

def get_domain_id(smc_ip, smc_username, smc_password):
    XSRF_HEADER_NAME = 'X-XSRF-TOKEN'
    url = "https://" + smc_ip + "/token/v2/authenticate"
    login_request_data = {"username": smc_username,"password": smc_password}
    api_session = requests.Session()
    response = api_session.request("POST", url, verify=False, data=login_request_data)

    if(response.status_code == 200):
        for cookie in response.cookies:
            if DEBUG:
                print(cookie)
            if cookie.name == 'XSRF-TOKEN':
                api_session.headers.update({XSRF_HEADER_NAME: cookie.value})
                break
            
        url = 'https://' + smc_ip + '/sw-reporting/v1/tenants/'
        request_headers = {'Content-type': 'text/plain', 'Accept': 'text/plain'}
        response = api_session.request("GET", url, verify=False, headers=request_headers)
        if DEBUG:
            print("After Tenants get")


        # If successfully able to add the tag (host group)
        if (response.status_code == 200):
            print("")
            print("Domain information retreived ...")
            if DEBUG:
                print(response.text)   
            response_json = json.loads(response.text)
            domain_id = response_json["data"][0]["id"]
            uri = 'https://' + smc_ip + '/token'
            response = api_session.delete(uri, timeout=30, verify=False)
            api_session.headers.update({XSRF_HEADER_NAME: None})
            return domain_id
        else:
            print("Unable to get DOMAIN ID response status code {}".format(response.status_code))


        #logout
        uri = 'https://' + smc_ip + '/token'
        response = api_session.delete(uri, timeout=30, verify=False)
        api_session.headers.update({XSRF_HEADER_NAME: None})
        return False
    else:
        return False




