#!/usr/bin/env python
from __future__ import print_function
import getpass
from apic_fnc import *
import argparse
import yaml

# Because it is in a different place on other systems.
try:
    import requests.packages.urllib3 as urllib3
except:
    import urllib3


# This will suppress warnings from logins without valid certificate
urllib3.disable_warnings()

__author__ = 'developer'

#TODO: Fix the imports


def main():
    base_fh = open('base_config.yml', 'r')

    base = yaml.load(base_fh, Loader=yaml.FullLoader)

    base_fh.close()

    options = argparse.ArgumentParser()
    options.add_argument("-a", "--apic", help="Name or IP of Apic device", required=True)
    options.add_argument("-u", "--user", help="Username to authenticate with", required=True)
    options.add_argument("-t", "--task", default='all',
                         help="Define the tasks to run can be comma seperated list \
                               ")
    options.add_argument("-p", "--password", help="Password used to authenticate with")

    args = options.parse_args()

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("APIC Password: ")

    #apic_ip = host_dns(args.apic, return_ip=True)

    md = apic_login(args.apic, args.user, password)

    # if 'http_redirect' in args.task or 'all' in args.task:
    #     """ Configure HTTP to HTTPS redirect """
    #     print("Processing task http redirect...")
    #     set_http_redirect(md, base['http_redirect'])

    if 'default_pod_policy' in args.task or 'all' in args.task:
        create_poddefault_policy(md)

    if 'power-mode' in args.task or 'all' in args.task:
        """ Configure the Power Redundancy Mode """
        print("Processing task power-mode...")
        for i in base['power_policy']:
            set_power_redundancy(md, i['name'], i['mode'], debug=False)

    if 'load_balancer_policy' in args.task or 'all' in args.task:
        """ Configure the fabric default load balancing policy """
        print("Processing task Load Balancer Policy...")
        set_fabric_balancer(md, base['dyn_loadbalance_mode'], base['loadbalance_mode'], debug=False)

    # if 'ntp' in args.task or 'all' in args.task:
    #     """ Configure NTP servers """
    #     print("Processing task NTP...")
    #     if type(base['ntp']) == dict:
    #         server = host_dns(("1.%s.%s" % (apic_ip, base['ntp']['server'])), return_ip=True)
    #         set_ntp_server(md, server, base['ntp']['epg'], prefer='true')
    #         server = host_dns(("2.%s.%s" % (apic_ip, base['ntp']['server'])), return_ip=True)
    #         set_ntp_server(md, server, base['ntp']['epg'], prefer='false')
    #     elif type(base['ntp']) == list:
    #         for i in base['ntp']:
    #             server = host_dns(i['server'], return_ip=True)
    #             set_ntp_server(md, server, i['epg'], prefer='false')
    #     else:
    #         print("Unable to configure NTP Servers please check config file")
    #
    # if 'dns' in args.task or 'all' in args.task:
    #     """ Configure DNS """
    #     print("Processing task DNS...")
    #     if type(base['dns']) == dict:
    #         server = host_dns(("1.%s.%s" % (apic_ip, base['dns']['server'])), return_ip=True)
    #         set_dns_srv(md, server, prefer='true')
    #         server = host_dns(("2.%s.%s" % (apic_ip, base['dns']['server'])), return_ip=True)
    #         set_dns_srv(md, server, prefer='false')
    #     elif type(base['dns']) == list:
    #         for i in base['dns']:
    #             server = host_dns(i['server'], return_ip=True)
    #             set_dns_srv(md, server, i['epg'], prefer='false')
    #     else:
    #         print("Unable to configure DNS Servers please check config file")
    #
    #     set_dns_domain(md, base['dns_domain'], base['dns_domain_epg'], prefer='true')
    #
    #     set_oob_dnslbl(md, 'default', debug=False)

    if 'll_pol' in args.task or 'all' in args.task:
        """ Configure Link Level Policies """
        print("Processing link level policies...")
        for i in base['link_level_pol']:
            print('  ',i['name'])
            create_interface_pol(md, i['name'], i['speed'], i['auto_neg'])

    if 'cdp_pol' in args.task or 'all' in args.task:
        """ Configure CDP Policy """
        print("Processing CDP policies...")
        for i in base['cdp_pol']:
            print('  ', i['name'])
            create_cdp_pol(md, i['name'], i['admin_state'])

    if 'lldp_pol' in args.task or 'all' in args.task:
        """ Configure LLDP Policy """
        print("Processing LLDP policies...")
        for i in base['lldp_pol']:
            print('  ', i['name'])
            create_lldp_pol(md, i['name'], i['rx_state'], i['tx_state'])

    if 'lacp_pol' in args.task or 'all' in args.task:
        """ Configure LACP Policy """
        print("Processing LACP policies...")
        for i in base['lacp_pol']:
            print('  ', i['name'])
            create_lacp_pol(md, i['name'], i['min_links'], i['max_links'], i['ctrl'], i['mode'])

    if 'stp_pol' in args.task or 'all' in args.task:
        """ Configure Spanning Tree Policy """
        print("Processing Spanning Tree policies...")
        for i in base['stp_pol']:
            print('  ', i['name'])
            create_stp_pol(md, i['name'], i['ctrl'])

    if 'physdom' in args.task or 'all' in args.task:
        print("Processing Physical Domains...")
        for i in base['phys_doms']:
            print('  ', i['name'])
            create_physdom(md, i['name'], i['vlan_pool_name'], i['vlan_pool_type'])

    if 'aep_pol' in args.task or 'all' in args.task:
        """ Configure Attachable Access Entity Profiles """
        print("Processing Attachable Access Entity Profiles...")
        for i in base['aep_prfl']:
            print('  ', i['name'])
            create_aep_prfl(md, i['name'], i['infra'], i['phys_dom'], infra_vlan=base['infra_vlan'])

    if 'vlan_pool' in args.task or 'all' in args.task:
        print("Processing Vlan Pools...")
        for i in base['vlan_pools']:
            print('  ', i['name'])
            create_vlan_pool(md, i['name'], i['type'], i['vlan_from'], i['vlan_to'], i['physdom_name'])

if __name__ == '__main__':
  main()