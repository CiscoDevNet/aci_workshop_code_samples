#!/usr/bin/env python
from __future__ import print_function
from apic_fnc import *
import argparse
import yaml
import getpass

# This will suppress warnings when logging to the APIC without valid certificate
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

__author__ = 'developer'


def sw_name_create(site_code, fabric, device):

    if site_code:
        name = site_code

    if device['location']:
        name += '-' + device['location']

    if fabric:
        name += '-fab' + str(fabric)
    else:
        name += '-fab'

    if device['node']:
        name += '-sw' + str(device['node'])

    return name


def main():
    options = argparse.ArgumentParser()
    options.add_argument("-a", "--apic", help="Name or IP of Apic device", required=True)
    options.add_argument("-u", "--user", help="Username to authenticate with", required=True)
    options.add_argument("-t", "--task", default='all',
                         help="Define the tasks to run can be comma seperated list \
                               ")
    options.add_argument("-p", "--password", help="Password used to authenticate with")
    options.add_argument("-f", "--file", help="Site specific configuration file", required=True)

    args = options.parse_args()

    site_fh = open(args.file, 'r')

    site = yaml.load(site_fh, Loader=yaml.FullLoader)

    site_fh.close()

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("APIC Password: ")

    # Prompt for passwords that can not stored in YAML file
    if 'tacacs_key' in site.keys():
        tacacs_key = site['tacacs_key']
    else:
        #tacacs_key = getpass.getpass("Enter TACACS Key: ")
        tacacs_key = '123'

    if 'backup' in site.keys():
        if 'username' in site['backup'].keys():
            backup_password = getpass.getpass("Enter Password for %s: " % site['backup']['username'])

    md = apic_login(args.apic, args.user, password)

    if 'initial_setup' in args.task:
        args.task = 'all'
        register_switches = True
    else:
        register_switches = False

    if 'datetime_format' in site.keys():
        if 'datetime' in args.task or 'all' in args.task:
            print("\n======================================")
            print("Task datetime: Updating timezone...")
            set_datetime_format(md, site['datetime_format']['site_tz'],
                                site['datetime_format']['offset_state'],
                                site['datetime_format']['display_format'])

    if 'create_vrf' in args.task or 'all' in args.task:
        print("\n======================================")
        print("Task create_vrf: Creating generic VRFs...")
        create_generic_vrf(md, 'internal-vrf')
        create_generic_vrf(md, 'dmz-vrf')

    if 'switches' in site.keys():
        if 'register_switches' in args.task or 'all' in args.task:

            # Add In-Band default Node Management EPG
            polUni = cobra.model.pol.Uni('')
            fvTenant = cobra.model.fv.Tenant(polUni, 'mgmt')
            mgmtMgmtP = cobra.model.mgmt.MgmtP(fvTenant, 'default')
            mgmtInB = cobra.model.mgmt.InB(mgmtMgmtP, matchT='AtleastOne', descr='', prio='unspecified', encap='unknown', name='default')
            mgmtRsMgmtBD = cobra.model.mgmt.RsMgmtBD(mgmtInB, tnFvBDName='inb')
            c = cobra.mit.request.ConfigRequest()
            c.addMo(mgmtMgmtP)
            md.commit(c)

            print("\n======================================")
            print("Task register_switches: Registering switches to the fabric...")
            leafpairs = site.get('switches', {}).get('Leafs')
            spines = site.get('switches', {}).get('Spines')
            boarders = site.get('switches', {}).get('Boarder_leafs')

            for switch in spines:
                hostname = sw_name_create(site['site_code'], site['fabric'], switch)
                print("Registering switch %s..." % hostname)
                register_switch(md, switch['node'], hostname, switch['serial'])

            for pair in leafpairs:
                for switch in leafpairs[pair]:
                    hostname = sw_name_create(site['site_code'], site['fabric'], switch)
                    print("Registering switch %s..." % hostname)
                    register_switch(md, switch['node'], hostname, switch['serial'])

            if boarders:
                for pair in boarders:
                    for switch in boarders[pair]:
                        hostname = sw_name_create(site['site_code'], site['fabric'], switch)
                        print("Registering switch %s..." % hostname)
                        register_switch(md, switch['node'], hostname, switch['serial'])

        if 'switch_mgmt' in args.task or 'all' in args.task:
            print("\n======================================")
            print("Task switch_mgmt:  Creating Node Mgmt Addresses")
            inband_gw = site['inband']['gateway']
            leafpairs = site.get('switches', {}).get('Leafs')
            spines = site.get('switches', {}).get('Spines')
            boarders = site.get('switches', {}).get('Boarder_leafs')

            for switch in spines:
                if 'outband_gw' in switch.keys():
                    outband_gw = switch['outband_gw']
                else:
                    outband_gw = site['outband_gw']
                hostname = sw_name_create(site['site_code'], site['fabric'], switch)
                print("Creating Node Mgmt ip addreses %s..." % hostname)
                create_node_mgmt_addr(md, switch['node'], inband_gw, switch['inband'], outband_gw, switch['outband'])

            for pair in leafpairs:
                for switch in leafpairs[pair]:
                    if 'outband_gw' in switch.keys():
                        outband_gw = switch['outband_gw']
                    else:
                        outband_gw = site['outband_gw']
                    hostname = sw_name_create(site['site_code'], site['fabric'], switch)
                    print("Creating Node Mgmt ip addreses %s..." % hostname)
                    create_node_mgmt_addr(md, switch['node'], inband_gw, switch['inband'], outband_gw, switch['outband'])

            if boarders:
                for pair in boarders:
                    for switch in boarders[pair]:
                        if 'outband_gw' in switch.keys():
                            outband_gw = switch['outband_gw']
                        else:
                            outband_gw = site['outband_gw']
                        hostname = sw_name_create(site['site_code'], site['fabric'], switch)
                        print("Creating Node Mgmt ip addreses %s..." % hostname)
                        create_node_mgmt_addr(md, switch['node'], inband_gw, switch['inband'], outband_gw, switch['outband'])

        if 'switch_groups' in args.task or 'all' in args.task:
            print("\n======================================")
            print("Task switch_groups:  Creating vPC groups and Interface Profiles")

            leafpairs = site.get('switches', {}).get('Leafs')
            boarders = site.get('switches', {}).get('Boarder_leafs')

            for lp in leafpairs:
                node_ids = []

                for i in leafpairs[lp]:
                    node_ids.append(i['node'])
                    swprfl_name = 'sw' + str(i['node']) + '-swPrfl'
                    ifprfl_name = 'sw' + str(i['node']) + '-ifPrfl'
                    create_switch_profile(md, swprfl_name, i['node'])
                    create_ifprfl(md, ifprfl_name, swprfl_name)

                swprfl_name = 'leafPair' + str(lp) + '-swPrfl'
                ifprfl_name = 'leafPair' + str(lp) + '-ifPrfl'
                vpc_grp = 'leafPair' + str(lp) + '-vpcGrp'
                vpc_pol = 'default'

                create_switch_profile(md, swprfl_name, node_ids)
                create_ifprfl(md, ifprfl_name, swprfl_name)

                create_vpc_policy_grp(md, vpc_grp, lp, node_ids, vpc_pol)

    # Configure Tacacs Servers
    if 'tacacs' in site.keys():
        if 'tacacs' in args.task or 'all' in args.task:
            print("\n======================================")
            print("Task TACACS:  Adding TACACS server and setting login domain")
            order = 1
            for tacacs in site['tacacs']:
                print('Creating TACACS %s (%s)...' % (tacacs['server'], tacacs['description']))
                add_tacacs_server(md, tacacs['server'], tacacs['description'], tacacs_key, order)
                order += 1
            login_domains(md)

    # Configure Backup Policy
    if 'backup' in site.keys():
        if 'backup' in args.task or 'all' in args.task:
            print("\n======================================")
            print("Task Backup Policy:  Adding Remote host and setting up Daily bacup policy")
            backup = site['backup']
            print('Creating Daily back to %s...' % backup['server'])
            create_backup_policy(md, backup['server'], backup['path'], backup['username'], backup_password)

    if 'bgp_policy' in site.keys():
        if 'bgp_policy' in args.task or 'all' in args.task:
            """This will set the BGP AS number and the RouterReflector Nodes"""
            print("Processing task bgp_policy...")

            if type(site['bgp_policy']['rr_nodes']) == int:
                rr_nodes = [site['bgp_policy']['rr_nodes']]
            else:
                rr_nodes = site['bgp_policy']['rr_nodes'].split(',')

            set_bgp_policy(md, site['bgp_policy']['site_as'], rr_nodes)

            create_poddefault_policy(md)

if __name__ == '__main__':
    main()
    print()
