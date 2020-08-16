#!/usr/bin/env python3
##########################################################
# if you need - you can disable cache (__pycache__)
# > bash# export PYTHONDONTWRITEBYTECODE=1
#
# Enable/Disable Verbose Developing Debug
# > bash# export DEBUG=1
# > bash# unset DEBUG
##########################################################
"""
First install all necessary libs
bash# pip3 install -r requirements.txt
"""

import argparse
import yaml
import http.server
import socketserver
import requests
import re
import ipaddress
from termcolor import colored
from pprint import pprint 
from requests.auth import HTTPBasicAuth
from jinja2 import Template

def load_config(file_name):
    with open(file_name) as file:
        cfg_params = yaml.load(file, Loader=yaml.FullLoader)
    cfg_params["header"]={
        'Authorization': 'Token ' + cfg_params["netbox_token"],
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    return cfg_params

def get_netbox_config(urn,cfg):
    url = cfg['netbox_url'] + urn + '?limit=0'
    
    rest_call = requests.get(url, headers=cfg['header'])
    if rest_call.status_code != 200:
        return dict()
    if rest_call.status_code == 200:
        ret = rest_call.json()
        return ret['results']

def valid_ip(address):
    try: 
        ipaddress.ip_address(address)
        return True
    except:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='import.py')
    parser.add_argument('-d', '--dest', help='TFTP Destination folder', default='../../tftp'),
    parser.add_argument('-c', '--config', help='Netbox parameters YAML Config file', default='config.yaml'),
    args = parser.parse_args()
    kwargs = vars(args)

    nb_cfg = load_config(kwargs["config"])

    cfg_devices = get_netbox_config('api/dcim/devices/', nb_cfg)
    if_devices = get_netbox_config('api/dcim/interfaces/', nb_cfg)

    macs = dict()
    for each_if in if_devices:
        #print("Device: " + each_if['device']['name'] + " interface: " + each_if['name'] + " mac: "+ str(each_if['mac_address']))
        if re.match('^em0', each_if['name']) is not None:
            print('Device: '+each_if['device']['name']+' - managment em0 mac: '+ str(each_if['mac_address'])    )
            macs[each_if['device']['name']] = str(each_if['mac_address'])
    
    nb_import = dict()
    for each_device in cfg_devices:
        print("Device: " + each_device['name'] + " - SN: " + each_device['serial'] + " ip-device: "+ each_device['primary_ip']['address'])
        try:
            nb_import[each_device['serial']]
        except:
            nb_import[each_device['serial']]=dict()
        
        # MAC
        mac = macs[each_device.get('name')]
        if mac != 'None' and mac is not None:
            nb_import[each_device['serial']]['mac'] = mac
        #Hostname
        nb_import[each_device['serial']]['hostname'] = each_device['name']

        # IP + Mask
        nb_import[each_device['serial']]['ip'] = str(ipaddress.IPv4Interface(each_device['primary_ip']['address']).ip)
        nb_import[each_device['serial']]['subnet_mask'] = str(ipaddress.IPv4Interface(each_device['primary_ip']['address']).netmask)

        # Router / Geteway
        device_network = ipaddress.ip_interface(each_device['primary_ip']['address']).network
        if valid_ip(nb_cfg['config']['router']):
            nb_import[each_device['serial']]['router'] = nb_cfg['config']['router']
        elif nb_cfg['config']['router'] == -1:
            gw = ipaddress.IPv4Network(device_network)[-2]
            nb_import[each_device['serial']]['router'] = str(gw)
        else:
            gw = ipaddress.IPv4Network(device_network)[1]
            nb_import[each_device['serial']]['router'] = str(gw)

        # Domain
        if nb_cfg['config'].get('domain') is not None:
            nb_import[each_device['serial']]['domain'] = nb_cfg['config']['domain']

        # name_server
        if nb_cfg['config'].get('name_server'):
            nb_import[each_device['serial']]['name_server'] =nb_cfg['config']['name_server']

        # lease_time
        if nb_cfg['config'].get('lease_time'):
            nb_import[each_device['serial']]['lease_time'] = nb_cfg['config']['lease_time']
            
        # tftp_server_name
        if nb_cfg['config'].get('tftp_server_name'):
            nb_import[each_device['serial']]['tftp_server_name'] = nb_cfg['config']['tftp_server_name']

        # boot-file-name
        if nb_cfg['config'].get('boot-file-name'):
            nb_import[each_device['serial']]['boot-file-name'] = nb_cfg['config']['boot-file-name']

        # tftp_server_address
        if nb_cfg['config'].get('tftp_server_address'):
            nb_import[each_device['serial']]['tftp_server_address'] = nb_cfg['config']['tftp_server_address']

        # vendor_specific
        config_file_name = "nb_"+each_device['serial']+".sh"
        if nb_cfg['config'].get('vendor_specific') == True:
            nb_import[each_device['serial']]['vendor_specific'] = "1:"+config_file_name+",3:tftp"

        # Generate Config
        with open('templates/junos.j2') as file_:
            template = Template(file_.read())
        filebuffer = template.render(nb_import[each_device['serial']], em0 = each_device['primary_ip']['address'])

        print("Device: " + each_device['name'] + " - generate config file: " +config_file_name)
        filehandle = open(kwargs["dest"]+'/'+config_file_name, "w")
        filehandle.writelines(filebuffer)
        filehandle.close()

    print("Generate YAML DHCP config file: nb_import.yaml")
    with open(kwargs["dest"]+'/nb_import.yml', 'w') as outfile:
        yaml.dump(nb_import, outfile, default_flow_style=False)