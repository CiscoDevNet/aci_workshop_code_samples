#!/usr/bin/env python
# -*- coding: utf-8 -*-
# The above line is needed to help decoding yaml data copied from wiki sites.

"""
Read config from file input and push to APIC.
- Desired configuration is YAML format
- Requires ACI SDK

"""

# TODO - Validate exported contarcts have been exported for the reporting feature.
# TODO - Add to delete option: Extra contracts on External Network Instances
# TODO - Add Snapshot for roll back options
# TODO - Check EPG VMM Domains in report mode
# TODO - Export contracts that are already created on the APIC

import argparse
import getpass
import yaml
import time
import sys
import cobra.mit.access
import cobra.mit.session
import cobra.mit.request
import cobra.mit.naming
import cobra.model.fv
import cobra.model.l3ext
import cobra.model.pol
import cobra.model.vz
import xml.dom.minidom
import ipaddr

from cobra.internal.codec.xmlcodec import toXMLStr
from cobra.mit.request import ClassQuery
from cobra.mit.request import DnQuery

# Because it is in a different place on other systems.
try:
    import requests.packages.urllib3 as urllib3
except:
    import urllib3


# This will suppress warnings from logins without valid certificate
urllib3.disable_warnings()

__author__ = 'developer'

version = '1.1.2'


class ApicSession:
    """
    """

    def __init__(self, apic, username, password, test=False):
        self.apic = apic
        self.username = username
        self.password = password
        self.login_timer = 0
        self.test = test
        self.change_made = False
        self.yaml_to_xml = False
        self.mo_dir = False
        self.show_xml = False

    def login(self):
        if self.yaml_to_xml:
            return ''
        self.login_timer = time.time()
        url = 'https://%s' % self.apic
        print url
        login_session = cobra.mit.session.LoginSession(url, self.username, self.password)
        self.mo_dir = cobra.mit.access.MoDirectory(login_session)
        # Don't crash and burn on bad password.
        try:
            self.mo_dir.login()
        except cobra.mit.session.LoginError as errorCode:
            print >> sys.stderr, "Error {}: {}".format(errorCode.error, errorCode.reason)
            sys.exit(3)
        print 'Logged into %s\n' % self.apic

    def search_by_dn(self, dn):
        if self.yaml_to_xml:
            return ''
        # Refresh login auth if needed
        if (time.time() - self.login_timer) > 500:
            self.mo_dir.reauth()
            self.login_timer = time.time()
        dn_search = self.mo_dir.lookupByDn(dnStrOrDn=dn)
        return dn_search

    def search_for_children(self, dn, class_filter, return_attribute, prop_incl='config-only', prop_filter=''):
        if self.yaml_to_xml:
            return ''
        # Refresh login auth if needed
        if (time.time() - self.login_timer) > 500:
            self.mo_dir.reauth()
            self.login_timer = time.time()

        # Build the query
        query = DnQuery(dn)
        query.queryTarget = 'children'
        query.classFilter = class_filter
        query.propInclude = prop_incl
        query.propFilter = prop_filter

        # Search
        result = self.mo_dir.query(query)
        return_list = []
        for i in result:
            return_list.append(i.__getattribute__(return_attribute))

        return return_list

    def dn_query_attribute(self, dn, return_attribute, prop_incl='config-only'):
        if self.yaml_to_xml:
            return ''
        # Refresh login auth if needed
        if (time.time() - self.login_timer) > 500:
            self.mo_dir.reauth()
            self.login_timer = time.time()

        # Build the query
        query = DnQuery(dn)
        query.queryTarget = 'self'
        query.propInclude = prop_incl
        query.propFilter = return_attribute

        # Search
        result = self.mo_dir.query(query)

        return result.__getattribute__(return_attribute)

    def commit(self, mo, change="Config from YAML file"):
        # Create a config request from mo
        c = cobra.mit.request.ConfigRequest()
        c.addMo(mo)

        # Commit to APIC
        if self.yaml_to_xml:
            xml_string = xml.dom.minidom.parseString(toXMLStr(mo))
            pretty_xml_as_string = xml_string.toprettyxml()
            print pretty_xml_as_string
        elif not self.test:
            if self.show_xml:
                xml_string = xml.dom.minidom.parseString(toXMLStr(mo))
                pretty_xml_as_string = xml_string.toprettyxml()
                print pretty_xml_as_string
            else:
                # Refresh login auth if needed
                if (time.time() - self.login_timer) > 500:
                    self.mo_dir.reauth()
                    self.login_timer = time.time()
                self.mo_dir.commit(c)
                print '%s committed on APIC' % change
        else:
            print 'Changes not committed to APIC (test only)'
        self.change_made = True


class Create:
    def __init__(self, mo_dir):
        self.mo_dir = mo_dir
    
    # Create tenant
    def tenant(self, tenant_name):
        """

        :param tenant_name:
        :return:
        """
    
        # Build MO
        top_mo = cobra.model.pol.Uni('')
        fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)
    
        # Push to APIC
        self.mo_dir.commit(fv_tenant, 'Tenant')
    
    # Create filter from YAML
    def filter(self, tenant_name, f):
        """

        :param tenant_name:
        :param f:
        :return:
        """
    
        # Build MO
        top_mo = cobra.model.pol.Uni('')
        fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)
        vz_filter = cobra.model.vz.Filter(fv_tenant, name=f['name'])
    
        # Process entries
        for entry in f['entries']:
            entry_details = {}
    
            # Translate YAML attributes to ACI format
            if 'etherType' in entry.keys():
                entry_details['etherT'] = entry['etherType']
            else:
                entry_details['etherT'] = 'ip'
            if 'protocol' in entry.keys():
                entry_details['prot'] = entry['protocol']
            else:
                entry_details['prot'] = 'unspecified'
            if 'dst-start' in entry.keys():
                entry_details['dFromPort'] = entry['dst-start']
            else:
                entry_details['dFromPort'] = 'unspecified'
            if 'dst-end' in entry.keys():
                entry_details['dToPort'] = entry['dst-end']
            else:
                entry_details['dToPort'] = 'unspecified'
            if 'src-start' in entry.keys():
                entry_details['sFromPort'] = entry['src-start']
            else:
                entry_details['sFromPort'] = 'unspecified'
            if 'src-end' in entry.keys():
                entry_details['sToPort'] = entry['src-end']
            else:
                entry_details['sToPort'] = 'unspecified'
            if 'tcpFlags' in entry.keys():
                counter = 0
                for flag in entry['tcpFlags']:
                    if counter == 0:
                        entry_details['tcpRules'] = str(flag)
                        counter += 1
                    else:
                        entry_details['tcpRules'] += ','
                        entry_details['tcpRules'] += str(flag)
            else:
                entry_details['tcpRules'] = 'unspecified'
    
            cobra.model.vz.Entry(vz_filter,
                                 name=entry['name'],
                                 etherT=entry_details['etherT'],
                                 prot=entry_details['prot'],
                                 sFromPort=entry_details['sFromPort'],
                                 sToPort=entry_details['sToPort'],
                                 dFromPort=entry_details['dFromPort'],
                                 dToPort=entry_details['dToPort'],
                                 tcpRules=entry_details['tcpRules']
                                 )
    
            # Push changes to apic
            self.mo_dir.commit(fv_tenant, 'Filter')
    
    # Create entry under filter DN
    def entry(self, filter_dn, entry):
        """

        :param filter_dn:
        :param entry:
        :return:
        """
    
        # Look up filter DN
        filter_mo = self.mo_dir.search_by_dn(filter_dn)
    
        # Process entry
        entry_details = {}
    
        # Translate YAML attributes to ACI format
        if 'etherType' in entry.keys():
            entry_details['etherT'] = entry['etherType']
        else:
            entry_details['etherT'] = 'ip'
        if 'protocol' in entry.keys():
            entry_details['prot'] = entry['protocol']
        else:
            entry_details['prot'] = 'unspecified'
        if 'dst-start' in entry.keys():
            entry_details['dFromPort'] = entry['dst-start']
        else:
            entry_details['dFromPort'] = 'unspecified'
        if 'dst-end' in entry.keys():
            entry_details['dToPort'] = entry['dst-end']
        else:
            entry_details['dToPort'] = 'unspecified'
        if 'src-start' in entry.keys():
            entry_details['sFromPort'] = entry['src-start']
        else:
            entry_details['sFromPort'] = 'unspecified'
        if 'src-end' in entry.keys():
            entry_details['sToPort'] = entry['src-end']
        else:
            entry_details['sToPort'] = 'unspecified'
        if 'tcpFlags' in entry.keys():
            counter = 0
            for flag in entry['tcpFlags']:
                if counter == 0:
                    entry_details['tcpRules'] = str(flag)
                    counter += 1
                else:
                    entry_details['tcpRules'] += ','
                    entry_details['tcpRules'] += str(flag)
        else:
            entry_details['tcpRules'] = 'unspecified'
    
        cobra.model.vz.Entry(filter_mo,
                             name=entry['name'],
                             etherT=entry_details['etherT'],
                             prot=entry_details['prot'],
                             sFromPort=entry_details['sFromPort'],
                             sToPort=entry_details['sToPort'],
                             dFromPort=entry_details['dFromPort'],
                             dToPort=entry_details['dToPort'],
                             tcpRules=entry_details['tcpRules']
                             )
    
        # Push to APIC
        self.mo_dir.commit(filter_mo, 'Filter Entry')
    
    # Create contract
    def contract(self, tenant_name, contract):
        """

        :param tenant_name:
        :param contract:
        :return:
        """
    
        # Build MO
        top_mo = cobra.model.pol.Uni('')
        fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)
        description = ''
        if 'description' in contract.keys():
            description = contract['description']
        vz_br_cp = cobra.model.vz.BrCP(fv_tenant, name=contract['name'], scope=contract['scope'], descr=description)
    
        # subjects
        for subject in contract['subjects']:
            # Would like to replace 'isUniDirectional' with 'both-directions' so this is a temp work around.
            if 'both-directions' in subject.keys():
                if not subject['both-directions']:
                    subject['isUniDirectional'] = True
                elif subject['both-directions']:
                    subject['isUniDirectional'] = False
    
            if 'isUniDirectional' in subject.keys():
                vz_subj = cobra.model.vz.Subj(vz_br_cp, name=subject['name'])
    
                # Unidirectional contract
                if subject['isUniDirectional']:
    
                    # Filters into EPG
                    if 'filtersIntoEPG' in subject.keys():
                        vz_in_term = cobra.model.vz.InTerm(vz_subj)
                        for f in subject['filtersIntoEPG']:
                            cobra.model.vz.RsFiltAtt(vz_in_term, tnVzFilterName=f)
                        cobra.model.vz.OutTerm(vz_subj, descr="", name="", prio="unspecified")
                    if 'filters' in subject.keys():
                        vz_in_term = cobra.model.vz.InTerm(vz_subj)
                        for f in subject['filters']:
                            cobra.model.vz.RsFiltAtt(vz_in_term, tnVzFilterName=f)
                        cobra.model.vz.OutTerm(vz_subj, descr="", name="", prio="unspecified")
    
                    # Filters out of EPG
                    if 'filtersOutOfEPG' in subject.keys():
                        vz_out_term = cobra.model.vz.OutTerm(vz_subj, descr="", name="", prio="unspecified")
                        for f in subject['filtersOutOfEPG']:
                            cobra.model.vz.RsFiltAtt(vz_out_term, tnVzFilterName=f)
    
                # Bi-directional subject
                if not subject['isUniDirectional']:
                    vz_subj = cobra.model.vz.Subj(vz_br_cp, name=subject['name'])
                    """ Bi-directional subjects """
                    if 'filters' in subject.keys():
                        for f in subject['filters']:
                            cobra.model.vz.RsSubjFiltAtt(vz_subj, tnVzFilterName=f)
    
            # If direction not specified, then assume bi-directional
            else:
                """ Assume bi-directional if not specified """
                vz_subj = cobra.model.vz.Subj(vz_br_cp, name=subject['name'], revFltPorts="no")
                if 'filters' in subject.keys():
                    for f in subject['filters']:
                        cobra.model.vz.RsSubjFiltAtt(vz_subj, tnVzFilterName=f)
    
        # Push changes to apic
        self.mo_dir.commit(fv_tenant, 'Contract')
    
        if 'export-to' in contract.keys():
            for export_tenant_name in contract['export-to']:
                export_fv_tenant = cobra.model.fv.Tenant(top_mo, name=export_tenant_name)
                import_contract_name = cobra.model.vz.CPIf(export_fv_tenant, name=contract['name'])
                import_contract = cobra.model.vz.RsIf(import_contract_name, tDn="uni/tn-%s/brc-%s" % (tenant_name,
                                                                                                      contract['name']))
                # Push changes to apic
                self.mo_dir.commit(export_fv_tenant, 'Import Contract')
    
    # Create subject
    def subject(self, contract_dn, subject):
        """

        :param contract_dn:
        :param subject:
        :return:
        """
    
        # Get contract MO
        contract_mo = self.mo_dir.search_by_dn(contract_dn)
    
        # Would like to replace 'isUniDirectional' with 'both-directions' so this is a temp work around.
        if 'both-directions' in subject.keys():
            if not subject['both-directions']:
                subject['isUniDirectional'] = True
            elif subject['both-directions']:
                subject['isUniDirectional'] = False
    
        # Add subject
        vz_subj = cobra.model.vz.Subj(contract_mo, name=subject['name'])
        if 'isUniDirectional' in subject.keys():
    
            # Unidirectional contract
            if subject['isUniDirectional']:
    
                # Filters into EPG
                if 'filtersIntoEPG' in subject.keys():
                    vz_in_term = cobra.model.vz.InTerm(vz_subj)
                    for f in subject['filtersIntoEPG']:
                        cobra.model.vz.RsFiltAtt(vz_in_term, tnVzFilterName=f)
    
                # Filters out of EPG
                if 'filtersOutOfEPG' in subject.keys():
                    vz_out_term = cobra.model.vz.OutTerm(vz_subj)
                    for f in subject['filtersOutOfEPG']:
                        cobra.model.vz.RsFiltAtt(vz_out_term, tnVzFilterName=f)
    
            # Bi-directional subject
            if not subject['isUniDirectional']:
                vz_subj = cobra.model.vz.Subj(contract_mo, name=subject['name'])
                """ Bi-directional subjects """
                if 'filters' in subject.keys():
                    for f in subject['filters']:
                        cobra.model.vz.RsSubjFiltAtt(vz_subj, tnVzFilterName=f)
    
        # If direction not specified, then assume bi-directional
        else:
            """ Assume bi-directional if not specified """
            vz_subj = cobra.model.vz.Subj(contract_mo, name=subject['name'])
            if 'filters' in subject.keys():
                for f in subject['filters']:
                    cobra.model.vz.RsSubjFiltAtt(vz_subj, tnVzFilterName=f)
    
        # Push changes to apic
        self.mo_dir.commit(contract_mo, 'Contract Subjects')
    
    # Create l3out
    def l3out(self, tenant_name, l3out):
        """

        :param tenant_name:
        :param l3out:
        :return:
        """
    
        # Build MO
        top_mo = cobra.model.pol.Uni('')
        fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)
        l3_ext_out = cobra.model.l3ext.Out(fv_tenant, name=l3out['name'])
    
        # External networks
        for ext_net in l3out['external-networks']:
            l3_ext_inst_p = cobra.model.l3ext.InstP(l3_ext_out, name=ext_net['name'])
    
            # Network ranges
            if 'range' in ext_net.keys():
                if ext_net['range']:
                    for network in ext_net['range']:
                        cobra.model.l3ext.Subnet(l3_ext_inst_p, ip=network)
    
            # Contracts
            if 'contracts' in ext_net.keys():
                contracts = ext_net['contracts']
    
                # Provide contracts
                if 'provide' in contracts.keys():
                    if contracts['provide']:
                        for prov in contracts['provide']:
                            if isinstance(prov, dict):
                                prov = prov['name']
                            cobra.model.fv.RsProv(l3_ext_inst_p, tnVzBrCPName=prov)
    
                # Consume contracts
                if 'consume' in contracts.keys():
                    if contracts['consume']:
                        for cons in contracts['consume']:
                            if isinstance(cons, dict):
                                cons = cons['name']
                            cobra.model.fv.RsCons(l3_ext_inst_p, tnVzBrCPName=cons)
    
                # Consume imported contracts
                if 'consume-imported' in contracts.keys():
                        for consume_imported in contracts['consume-imported']:
                            if isinstance(consume_imported, dict):
                                consume_imported = consume_imported['name']
                            cobra.model.fv.RsConsIf(l3_ext_inst_p, tnVzCPIfName=consume_imported)
    
        # Push changes to apic
        self.mo_dir.commit(fv_tenant, 'L3OUT')

    def subnet(self, l3out_dn, ext_net, subnet):
        """

        :param l3out_dn:
        :param ext_net:
        :return:
        """

        # Get L3 out MO
        l3out_mo = self.mo_dir.search_by_dn(l3out_dn)

        # Add external networks
        l3_ext_inst_p = cobra.model.l3ext.InstP(l3out_mo, name=ext_net['name'])

        cobra.model.l3ext.Subnet(l3_ext_inst_p, ip=subnet)

        # Push changes to apic
        self.mo_dir.commit(l3out_mo, 'ExtNet')

    # Create external network
    def ext_net(self, l3out_dn, ext_net):
        """

        :param l3out_dn:
        :param ext_net:
        :return:
        """
    
        # Get L3 out MO
        l3out_mo = self.mo_dir.search_by_dn(l3out_dn)
    
        # Add external networks
        l3_ext_inst_p = cobra.model.l3ext.InstP(l3out_mo, name=ext_net['name'])
    
        # Network ranges
        if 'range' in ext_net.keys():
            if ext_net['range']:
                for network in ext_net['range']:
                    cobra.model.l3ext.Subnet(l3_ext_inst_p, ip=network)
    
        # Contracts
        if 'contracts' in ext_net.keys():
            contracts = ext_net['contracts']
    
            # Provided contracts
            if 'provide' in contracts.keys():
                if contracts['provide']:
                    for prov in contracts['provide']:
                        if isinstance(prov, dict):
                                prov = prov['name']
                        cobra.model.fv.RsProv(l3_ext_inst_p, tnVzBrCPName=prov)
    
            # Consumed contracts
            if 'consume' in contracts.keys():
                if contracts['consume']:
                    for cons in contracts['consume']:
                        if isinstance(cons, dict):
                                cons = cons['name']
                        cobra.model.fv.RsCons(l3_ext_inst_p, tnVzBrCPName=cons)
    
            # Comsume Imported Contracts
            if 'consume-imported' in contracts.keys():
                if contracts['consume-imported']:
                    for consume_imported in contracts['consume-imported']:
                        if isinstance(consume_imported, dict):
                                consume_imported = consume_imported['name']
                        cobra.model.fv.RsConsIf(l3_ext_inst_p, tnVzCPIfName=consume_imported)
    
        # Push changes to apic
        self.mo_dir.commit(l3out_mo, 'ExtNet')
    
    # Create a provided contract on a VRF
    def vrf_prov_contract(self, vrf_dn, contract, vrf_mo):
        """

        :param vrf_dn:
        :param contract:
        :param vrf_mo:
        :return:
        """
    
        if not self.mo_dir.test:
    
            # Grab the VRF MO
            if not vrf_mo:
                vrf_mo = self.mo_dir.search_by_dn(vrf_dn)
    
            # Add the provided contract
            vz_any = cobra.model.vz.Any(vrf_mo, matchT='AtleastOne', name='')
            cobra.model.vz.RsAnyToProv(vz_any, tnVzBrCPName=contract)
    
            # Push changes to apic
            self.mo_dir.commit(vrf_mo)
    
    # Create a consumed contract on a VRF
    def vrf_cons_contract(self, vrf_dn, contract, vrf_mo):
        """

        :param vrf_dn:
        :param contract:
        :param vrf_mo:
        :return:
        """
    
        if not self.mo_dir.test:
    
            # Grab the VRF MO
            if not vrf_mo:
                vrf_mo = self.mo_dir.search_by_dn(vrf_dn)
    
            # Add the provided contract
            vz_any = cobra.model.vz.Any(vrf_mo, matchT='AtleastOne', name='')
            cobra.model.vz.RsAnyToCons(vz_any, tnVzBrCPName=contract)
    
            # Push changes to apic
            self.mo_dir.commit(vrf_mo)
    
    def bridge_domain(self, tenant_name, bridge_domain, bridge_domain_dn):
        """

        :param tenant_name:
        :param bridge_domain:
        :param bridge_domain_dn:
        :return:
        """
    
        # Get Bridge Domain info from APIC
        apic_bridge_domain = self.mo_dir.search_by_dn(bridge_domain_dn)
    
        if apic_bridge_domain:
            bd_details = apic_bridge_domain.__dict__
        else:
            bd_details = {'bd_description': '',
                          'bd_arp_flood': 'no',
                          'bd_unknown_unicast': 'proxy',
                          'bd_unknown_multicast': 'flood',
                          'subnet_learning_only': 'no'}

        # Build MO
        top_mo = cobra.model.pol.Uni('')
        fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)

        if 'description' in bridge_domain.keys():
            bd_details['bd_description'] = bridge_domain['description']
        else:
            bd_details['bd_description'] = ''
        if 'arp-flood' in bridge_domain.keys():
            bd_details['bd_arp_flood'] = bridge_domain['arp-flood']
        if 'unknown-unicast' in bridge_domain.keys():
            bd_details['bd_unknown_unicast'] = bridge_domain['unknown-unicast']
            if bridge_domain['unknown-unicast'] == 'flood':
                bd_details['bd_arp_flood'] = 'yes'
        if 'unknown-multicast' in bridge_domain.keys():
            bd_details['bd_unknown_multicast'] = bridge_domain['unknown-multicast']
        elif apic_bridge_domain:
            bd_details['bd_unknown_multicast'] = bd_details['unkMacUcastAct']
        if 'subnet-learning-only' in bridge_domain.keys():
            bd_details['subnet_learning_only'] = bridge_domain['subnet-learning-only']
        elif apic_bridge_domain:
            bd_details['subnet_learning_only'] = bd_details['limitIpLearnToSubnets']
    
        fv_bd = cobra.model.fv.BD(fv_tenant,
                                  name=bridge_domain['name'],
                                  descr=bd_details['bd_description'],
                                  unkMacUcastAct=bd_details['bd_unknown_unicast'],
                                  arpFlood=bd_details['bd_arp_flood'],
                                  unkMcastAct=bd_details['bd_unknown_multicast'],
                                  limitIpLearnToSubnets=bd_details['subnet_learning_only'])

        if 'vrf' in bridge_domain.keys():
            fv_rs_ctx = cobra.model.fv.RsCtx(fv_bd, tnFvCtxName=bridge_domain['vrf'])

        if 'subnets' in bridge_domain.keys():
            sub_preferred_set = False
            for sub in bridge_domain['subnets']:
                sub_ip = sub['gateway-ip']
                if 'scope' in sub.keys():
                    sub_scope = sub['scope']
                else:
                    sub_scope = 'private'
    
                if not sub_preferred_set:
                    if 'preferred' in sub.keys():
                        sub_preferred = sub['preferred']
                        sub_preferred_set = True
                    else:
                        sub_preferred = 'no'
                else:
                    print 'ERROR: More than one subnet has been set as Preferred, please check your YAML file'
                    sub_preferred = 'no'
    
                fv_subnet = cobra.model.fv.Subnet(fv_bd, ip=sub_ip, scope=sub_scope, preferred=sub_preferred)
    
        if 'associated-l3-outs' in bridge_domain.keys():
            for l3_out in bridge_domain['associated-l3-outs']:
                fv_rs_bd_to_out = cobra.model.fv.RsBDToOut(fv_bd, tnL3extOutName=l3_out)
    
        # Push changes to apic
        self.mo_dir.commit(fv_tenant, 'Bridge Domain')
    
    def app_profile(self, tenant_name, app_profile):
        """

        :param tenant_name:
        :param app_profile:
        :return:
        """
    
        # Build MO
        top_mo = cobra.model.pol.Uni('')
        fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)
    
        if 'description' in app_profile.keys():
            ap_description = app_profile['description']
        else:
            ap_description = ' '
    
        fv_ap = cobra.model.fv.Ap(fv_tenant, name=app_profile['name'], descr=ap_description)
    
        # Push changes to apic
        self.mo_dir.commit(fv_tenant, 'App-Profile')
    
    def epg(self, tenant_name, epg, app_profile_name):
        """

        :param tenant_name:
        :param epg:
        :param app_profile_name:
        :return:
        """
    
        # Build MO
        top_mo = cobra.model.pol.Uni('')
        fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)
        fv_ap = cobra.model.fv.Ap(fv_tenant, name=app_profile_name)
    
        # for epg in app_profile['epgs']:
        if 'description' in epg.keys():
            epg_description = epg['description']
        else:
            epg_description = ' '
        fv_epg = cobra.model.fv.AEPg(fv_ap, name=epg['name'], descr=epg_description)
    
        if 'bridge-domain' in epg.keys():
            fv_rs_bd = cobra.model.fv.RsBd(fv_epg, tnFvBDName=epg['bridge-domain'])
        if 'contracts' in epg.keys():
            if 'provide' in epg['contracts'].keys():
                if epg['contracts']['provide']:
                    for provide in epg['contracts']['provide']:
                        if isinstance(provide, dict):
                            provide = provide['name']
                        fv_rs_prov = cobra.model.fv.RsProv(fv_epg, tnVzBrCPName=provide)
            if 'consume' in epg['contracts'].keys():
                for consume in epg['contracts']['consume']:
                    if isinstance(consume, dict):
                        consume = consume['name']
                    fv_rs_cons = cobra.model.fv.RsCons(fv_epg, tnVzBrCPName=consume)
            if 'consume-imported' in epg['contracts'].keys():
                for consume_imported in epg['contracts']['consume-imported']:
                    if isinstance(consume_imported, dict):
                        consume_imported = consume_imported['name']
                    cobra.model.fv.RsConsIf(fv_epg, tnVzCPIfName=consume_imported)
        if 'physical-domain' in epg.keys():
            fv_rs_dom_att = cobra.model.fv.RsDomAtt(fv_epg,
                                                    instrImedcy='immediate',
                                                    resImedcy='immediate',
                                                    tDn='uni/phys-' + epg['physical-domain'])
        if 'vmm-domains' in epg.keys():
            for vmm_domain in epg['vmm-domains']:
                fv_rs_dom_att = cobra.model.fv.RsDomAtt(fv_epg,
                                                        instrImedcy='lazy',
                                                        resImedcy='immediate',
                                                        tDn='uni/vmmp-VMware/dom-' + vmm_domain)
        if 'l2-domain' in epg.keys():
            fv_rs_dom_att = cobra.model.fv.RsDomAtt(fv_epg,
                                                    instrImedcy='immediate',
                                                    resImedcy='immediate',
                                                    tDn='uni/l2dom-' + epg['l2-domain'])
        if 'static-paths' in epg.keys():
            for path in epg['static-paths']:
                fv_rs_path_att = cobra.model.fv.RsPathAtt(fv_epg, instrImedcy='lazy',
                                                          encap=path['vlan'], mode=path['mode'],
                                                          tDn='topology/pod-1/protpaths-' + path['name'] + '/pathep-[' +
                                                              path['polgrp'] + ']')
        # Push changes to apic
        self.mo_dir.commit(fv_tenant, 'EPG')
    
    # Delete Policy on APIC
    def delete_mo(self, dn):
        """

        :param dn:
        :return:
        """
    
        # Grab MO
        mo = self.mo_dir.search_by_dn(dn)
    
        # Delete
        mo.delete()
        self.mo_dir.commit(mo)


class Validate:
    def __init__(self, mo_dir, create, alert_message, report_only=False, delete_on_apic=False, verbose=False):
        self.mo_dir = mo_dir
        self.report_only = report_only
        self.alert = alert_message
        self.delete_on_apic = delete_on_apic
        self.bridge_domain_subnets = []
        self.verbose = verbose
        self.create = create
        
    # Validate YAML file is formatted correctly
    def yaml(self, input_file):
        """

        :param input_file:
        :return:
        """
    
        try:
            yaml_input = ""
            with open(input_file, 'r') as fh:
                # This 'for loop' is needed to remove a bad character found when copying from wiki
                for line in fh.readlines():
                    # This line works on Linux
                    if ' ' in line:
                        yaml_input += line.replace(' ', ' ')
    
                    # This line works on Windows
                    elif '\xa0' in line:
                        yaml_input += line.replace('\xa0', ' ')
    
                    else:
                        yaml_input += line
    
            yaml_code = yaml.load(yaml_input, Loader=yaml.FullLoader)
            return yaml_code
        except yaml.YAMLError, exc:
            print 'ERROR: YAML formatting error in %s' % input_file
            print '\nError details:'
            print '%s\n' % exc
            sys.exit()
    
    # Check YAML filter entry against what is in APIC
    def entry(self, entry, entry_dn):
        """
    
        :param mo_dir_login:
        :param entry:
        :param entry_dn:
        :param report_only:
        :return:
        """
    
        # Convert YAML into APIC format
        port_num_to_text = {'20': 'ftp-data',
                            '25': 'smtp',
                            '53': 'dns',
                            '80': 'http',
                            '110': 'pop3',
                            '443': 'https',
                            '554': 'rtsp'}
    
        # Fill in the attributes
        entry_details = {}
        if 'etherType' in entry.keys():
            entry_details['etherT'] = entry['etherType']
        else:
            entry_details['etherT'] = 'ip'
    
        if 'protocol' in entry.keys():
            entry_details['prot'] = entry['protocol']
        else:
            entry_details['prot'] = 'unspecified'
    
        if 'dst-start' in entry.keys():
            if entry['dst-start'] in port_num_to_text.keys():
                entry_details['dFromPort'] = port_num_to_text[entry['dst-start']]
            else:
                entry_details['dFromPort'] = entry['dst-start']
        else:
            entry_details['dFromPort'] = 'unspecified'
    
        if 'dst-end' in entry.keys():
            if entry['dst-end'] in port_num_to_text.keys():
                entry_details['dToPort'] = port_num_to_text[entry['dst-end']]
            else:
                entry_details['dToPort'] = entry['dst-end']
        else:
            entry_details['dToPort'] = 'unspecified'
    
        if 'src-start' in entry.keys():
            if entry['src-start'] in port_num_to_text.keys():
                entry_details['sFromPort'] = port_num_to_text[entry['src-start']]
            else:
                entry_details['sFromPort'] = entry['src-start']
        else:
            entry_details['sFromPort'] = 'unspecified'
    
        if 'src-end' in entry.keys():
            if entry['src-end'] in port_num_to_text.keys():
                entry_details['sToPort'] = port_num_to_text[entry['src-end']]
            else:
                entry_details['sToPort'] = entry['src-end']
        else:
            entry_details['sToPort'] = 'unspecified'
    
        if 'tcpFlags' in entry.keys():
            counter = 0
            for flag in entry['tcpFlags']:
                if counter == 0:
                    entry_details['tcpRules'] = str(flag)
                    counter += 1
                else:
                    entry_details['tcpRules'] += ','
                    entry_details['tcpRules'] += str(flag)
        else:
            entry_details['tcpRules'] = ''
    
        # Grab the object from APIC
        apic_entry = self.mo_dir.search_by_dn(entry_dn)
    
        # Compare YAML to APIC
        validation_result = True
        for key in entry_details:
            if not entry_details[key] == apic_entry.__dict__[key]:
                print "Mismatch in '%s': YAML[%s]='%s' | APIC[%s]='%s'" % (entry_dn, key, entry_details[key], key,
                                                                           apic_entry.__dict__[key])
                # if report_only: # TEST NEW REPORTING
                #     fail_message = "Mismatch:\n"
                #     for line in entry_dn.split('/')[1:]:
                #         if line.startswith('tn-'):
                #             fail_message += "    Tenant: '%s" % line[3:]
                #         elif line.startswith('flt-'):
                #             fail_message += "\n    Filter: '%s" % line[4:]
                #         elif line.startswith('e-'):
                #             fail_message += "\n    Filter Entry: '%s'" % line[2:]
                #     print fail_message+'\n  > %s: %s (apic)  -  %s (yaml)\n' % (key, apic_entry.__dict__[key],
                #                                                                 entry_details[key])
                validation_result = False
    
        # Return result
        return validation_result
    
    # Validate subject
    def subject(self, subject_dn, subject):
        """

        :param subject_dn:
        :param subject:
        :return:
        """
    
        if 'both-directions' in subject.keys():
            if not subject['both-directions']:
                subject['isUniDirectional'] = True
            elif subject['both-directions']:
                subject['isUniDirectional'] = False
    
        validation_result = True
        # Unidirectional subject
        if 'isUniDirectional' in subject.keys():
    
            # Check for input terminal
            if subject['isUniDirectional']:
                in_term_dn = '%s/intmnl' % subject_dn
                out_term_dn = '%s/outtmnl' % subject_dn
                in_term_search = self.mo_dir.search_by_dn(in_term_dn)
                out_term_search = self.mo_dir.search_by_dn(out_term_dn)
                if not in_term_search and not out_term_search:
                    print "Mismatch in '%s': YAML='uni-directional' | APIC='bi-directional'\n" % subject_dn,
                    validation_result = False
                    return validation_result
    
                # Check filters out of EPG
                if 'filtersOutOfEPG' in subject.keys():
    
                    # Compare list of filters
                    out_term_dn = '%s/outtmnl' % subject_dn
                    out_search = self.mo_dir.search_by_dn(out_term_dn)
    
                    apic_filter_list = self.mo_dir.search_for_children(out_term_dn,
                                                                       'vzRsFiltAtt',
                                                                       'tnVzFilterName')
                    for f in subject['filtersOutOfEPG']:
                        if f not in apic_filter_list:
                            print "%sAPIC: FilterOutOfEPG '%s' in subject '%s'" % (self.alert, f, subject_dn)
                            validation_result = False
                    if self.report_only:
                        for f in apic_filter_list:
                            if f not in subject['filtersOutOfEPG']:
                                print "%sYAML: FilterOutOfEPG '%s' in subject '%s'" % (self.alert, f, subject_dn)
                                validation_result = False
    
                # Check filters into EPG
                if 'filtersIntoEPG' in subject.keys():
    
                    # Compare list of filters
                    in_term_dn = '%s/intmnl' % subject_dn
                    in_search = self.mo_dir.search_by_dn(in_term_dn)
    
                    apic_filter_list = self.mo_dir.search_for_children(in_term_dn,
                                                                       'vzRsFiltAtt',
                                                                       'tnVzFilterName')
                    for f in subject['filtersIntoEPG']:
                        if f not in apic_filter_list:
                            print "%sAPIC: FilterIntoEPG '%s' in subject '%s'" % (self.alert, f, subject_dn)
                            validation_result = False
                    if self.report_only:
                        for f in apic_filter_list:
                            if f not in subject['filtersIntoEPG']:
                                print "%sYAML: FilterIntoEPG '%s' in subject '%s'" % (self.alert, f, subject_dn)
                                validation_result = False
    
            # Bi-directional
            if not subject['isUniDirectional']:
                # Check if APIC is uni or bi directional
                in_term_dn = '%s/intmnl' % subject_dn
                if self.mo_dir.search_by_dn(in_term_dn):
                    print "Mismatch in '%s': YAML='bi-directional' | APIC='uni-directional'\n" % subject_dn
                    validation_result = False
                    return validation_result
    
                # Search for filters in APIC
                filter_list = self.mo_dir.search_for_children(subject_dn,
                                                               'vzRsSubjFiltAtt',
                                                               'tnVzFilterName')
                for f in subject['filters']:
                    if f not in filter_list:
                        print "%sAPIC: Filter '%s' in subject '%s'" % (self.alert, f, subject_dn)
                        validation_result = False
                if self.report_only:
                    for f in filter_list:
                        if f not in subject['filters']:
                            print "%sAPIC: Filter '%s' in subject '%s'" % (self.alert, f, subject_dn)
                            validation_result = False
    
        # Bi-directional subject
        else:
            # Check if APIC is uni or bi directional
            in_term_dn = '%s/intmnl' % subject_dn
            if self.mo_dir.search_by_dn(in_term_dn):
                print "Mismatch in '%s': YAML='bi-directional' | APIC='uni-directional'\n" % subject_dn
                validation_result = False
                return validation_result
    
            # Search for filters in APIC
            filter_list = self.mo_dir.search_for_children(subject_dn,
                                                          'vzRsSubjFiltAtt',
                                                          'tnVzFilterName')
            for f in subject['filters']:
                if f not in filter_list:
                    print "%sAPIC: Filter '%s' in subject '%s'" % (self.alert, f, subject_dn)
                    validation_result = False
            if self.report_only:
                for f in filter_list:
                    if f not in subject['filters']:
                        print "%sAPIC: Filter '%s' in subject '%s'" % (self.alert, f, subject_dn)
                        validation_result = False
    
        return validation_result

    def subnet_in_bd(self, subnet_ip, bd_subnets=None):

        subnet_ip = ipaddr.IPNetwork(subnet_ip)

        if not bd_subnets:
            bd_subnets = self.bridge_domain_subnets

        for bd_subnet in bd_subnets:
            if bd_subnet.Contains(subnet_ip):
                return bd_subnet

        return False

    # Validate the IP network ranges on external network
    def ip_nets(self, ext_net, ext_net_dn, l3out_dn):
        """

        :param ext_net
        :param ext_net_dn:
        :param l3out_dn:
        :return:
        """

        validation_result = True

        apic_range = self.mo_dir.search_for_children(ext_net_dn, 'l3extSubnet', 'ip')

        if not self.bridge_domain_subnets:
            # Get Subnets already assigned to Bridge Domains on the APIC
            fvCEpQuery = ClassQuery('fvSubnet')
            fvCEpQuery.queryTarget = 'self'
            for subnet in self.mo_dir.mo_dir.query(fvCEpQuery):
                temp_subnet = ipaddr.IPNetwork(subnet.ip)
                self.bridge_domain_subnets.append(temp_subnet)

        if self.verbose:
            print "Validating IP networks on '%s'" % ext_net_dn
        if ext_net['range']:
            for subnet in ext_net['range']:
                if subnet not in apic_range:
                    found_bd_subnet = self.subnet_in_bd(subnet)
                    if found_bd_subnet:
                        print "INFO: Not adding '%s' as '%s' found on a Bridge Domain." % (subnet, found_bd_subnet)
                    else:
                        print "%sAPIC: Subnet '%s' for external network '%s'" % (self.alert, subnet, ext_net_dn)
                        validation_result = False
                        if not self.report_only:
                            self.create.subnet(l3out_dn, ext_net, subnet)

        if self.report_only:
            for subnet in apic_range:
                if subnet not in ext_net['range'] and subnet not in self.bridge_domain_subnets:
                    print "%sYAML: Subnet '%s' for external network instance '%s'" % (self.alert,
                                                                                      subnet,
                                                                                      ext_net_dn)
                    if self.delete_on_apic:
                        del_subnet_dn = '%s/extsubnet-[%s]' % (ext_net_dn, subnet)
                        self.create.delete_mo(del_subnet_dn)
    
        return validation_result

    # Validate the contracts on an external network
    def ext_net_contracts(self, ext_net_dn, contracts):
        """

        :param ext_net_dn:
        :param contracts:
        :return:
        """
    
        validation_result = True
    
        # Search for contracts on APIC
        if 'provide' in contracts.keys():
            apic_provided_contracts = self.mo_dir.search_for_children(ext_net_dn, 'fvRsProv', 'tnVzBrCPName')
    
            # Check for contracts not found on APIC
            if contracts['provide']:
                for p in contracts['provide']:
                    if isinstance(p, dict):
                        p = p['name']
                    if p not in apic_provided_contracts:
                        print "%sAPIC: Provide contract '%s' for '%s'" % (self.alert, p, ext_net_dn)
                        validation_result = False
            # Check for extra contracts on APIC, not in YAML
            if self.report_only:
                for p in apic_provided_contracts:
                    if p not in contracts['provide']:
                        print "%sYAML: Provide contract '%s' for '%s'" % (self.alert, p, ext_net_dn)
                        if self.delete_on_apic:
                            pass  # PUT DELETE CODE HERE
                            validation_result = False
    
        # Search for contracts on APIC
        if 'consume' in contracts.keys():
            apic_consumed_contracts = self.mo_dir.search_for_children(ext_net_dn, 'fvRsCons', 'tnVzBrCPName')
    
            # Check for contracts not found on APIC
            if contracts['consume']:
                for c in contracts['consume']:
                    if isinstance(c, dict):
                        c = c['name']
                    if c:
                        if c not in apic_consumed_contracts:
                            print "%sAPIC: Consume contract '%s' for '%s'" % (self.alert, c, ext_net_dn)
                            validation_result = False
    
            # Check for extra contracts on APIC, not in YAML
            if self.report_only:
                for c in apic_consumed_contracts:
                    if isinstance(c, dict):
                        c = c['name']
                    if c not in contracts['consume']:
                        print "%sYAML: Consume contract '%s' for '%s'" % (self.alert, c, ext_net_dn)
                        if self.delete_on_apic:
                            pass  # PUT DELETE CODE HERE
                            validation_result = False
    
        # Search for Imported Contracts
        if 'consume-imported' in contracts.keys():
            apic_consumed_contract_interfaces = self.mo_dir.search_for_children(ext_net_dn, 'fvRsConsIf',
                                                                                'tnVzCPIfName')
            if contracts['consume-imported']:
                for contract in contracts['consume-imported']:
                    tenant_dn = ext_net_dn.split('/out-')[0]
                    if isinstance(contract, dict):
                        if not self.mo_dir.search_by_dn('%s/cif-%s' % (tenant_dn, contract['name'])):
                            contract = contract['name']
                    if not self.mo_dir.search_by_dn('%s/cif-%s' % (tenant_dn, contract)):
                        tenant_name = ext_net_dn.split('/')[1].split('tn-')[1]
                        print "%sAPIC: Imported contract '%s' not found in tenant '%s'" % (self.alert, contract,
                                                                                           tenant_name)
                        validation_result = False
                    if not self.mo_dir.search_by_dn('%s/rsconsIf-%s' % (ext_net_dn, contract)):
                        print "%sAPIC: Consume contract Interface '%s' for '%s'" % (self.alert, contract, ext_net_dn)
                        validation_result = False
    
            # Check for extra contracts on APIC, not in YAML
            if self.report_only:
                for c in apic_consumed_contract_interfaces:
                    if isinstance(c, dict):
                        c = c['name']
                    if c not in contracts['consume-imported']:
                        print "%sYAML: Consume contract Interface '%s' for '%s'" % (self.alert, c, ext_net_dn)
                        validation_result = False
    
        return validation_result

    def bridge_domain(self, bridge_domain, bridge_domain_dn):
        """

        :param bridge_domain:
        :param bridge_domain_dn:
        :return:
        """
    
        validation_result = True
    
        # Fill in the attributes
        bridge_domain_details = {}
        if 'unknown-unicast' in bridge_domain.keys():
            bridge_domain_details['unkMacUcastAct'] = bridge_domain['unknown-unicast']
        # else:
        #     bridge_domain_details['unkMacUcastAct'] = 'proxy'
        if 'unknown-multicast' in bridge_domain.keys():
            bridge_domain_details['unkMcastAct'] = bridge_domain['unknown-multicast']
        # else:
        #     bridge_domain_details['unkMcastAct'] = 'flood'
        if 'arp-flood' in bridge_domain.keys():
            bridge_domain_details['arpFlood'] = bridge_domain['arp-flood']
        # else:
        #     bridge_domain_details['arpFlood'] = 'no'
        if 'subnet-learning-only' in bridge_domain.keys():
            bridge_domain_details['limitIpLearnToSubnets'] = bridge_domain['subnet-learning-only']
    
        # Grab the object from APIC
        apic_bridge_domain = self.mo_dir.search_by_dn(bridge_domain_dn)
    
        # Compare YAML to APIC
        for key in bridge_domain_details:
            if not bridge_domain_details[key] == apic_bridge_domain.__dict__[key]:
                print "Mismatch in '%s' for %s: YAML='%s' | APIC='%s'" % (bridge_domain_dn, key,
                                                                          bridge_domain_details[key],
                                                                          apic_bridge_domain.__dict__[key])
                validation_result = False
    
        # Compare YAML to APIC (Subnets)
        if 'subnets' in bridge_domain.keys():
            for subnet in bridge_domain['subnets']:
                subnet_dn = '%s/subnet-[%s]' % (bridge_domain_dn, subnet['gateway-ip'])
    
                # Grab the object from APIC
                apic_subnet = self.mo_dir.search_by_dn(subnet_dn)
    
                # Compare YAML to APIC
                if apic_subnet:
                    for key in subnet:
                        if key == 'gateway-ip':
                            continue
                        if not subnet[key] == apic_subnet.__dict__[key]:
                            print "Mismatch in '%s': YAML='%s' | APIC '%s'" % (subnet_dn, subnet[key],
                                                                               apic_subnet.__dict__[key])
                            validation_result = False
    
        if 'associated-l3-outs' in bridge_domain.keys():
            for l3_out in bridge_domain['associated-l3-outs']:
                l3_out_dn = '%s/rsBDToOut-[%s]' % (bridge_domain_dn, l3_out)

                # Grab the object from APIC
                apic_l3_out_dn = self.mo_dir.search_by_dn(l3_out_dn)

                try:
                    apic_l3_out_dn.__dict__['tnL3extOutName']
                except AttributeError:
                    print "%sAPIC: Associated L3 Out '%s' in Bridge Domain '%s'" % (self.alert, l3_out,
                                                                                    bridge_domain['name'])

                    validation_result = False
    
        # Return result
        return validation_result

    def epg(self, epg, app_profile_dn):
        """

        :param epg:
        :param app_profile_dn:
        :return:
        """
    
        validation_result = True
    
        imported_contracts = []
    
        # for epg in app_profile['epgs']:
        epg_dn = '%s/epg-%s' % (app_profile_dn, epg['name'])
    
        if 'bridge-domain' in epg.keys():
            apic_epg_bd = self.mo_dir.search_by_dn(epg_dn+'/rsbd')
            if not epg['bridge-domain'] == apic_epg_bd.__dict__['tnFvBDName']:
                print "%sAPIC: Bridge Domain '%s' for EPG '%s'" % (self.alert, epg['bridge-domain'], epg_dn)
                validation_result = False
        if 'physical-domain' in epg.keys():
            phys_dn = '%s/rsdomAtt-[uni/phys-%s]' % (epg_dn, epg['physical-domain'])
            if not self.mo_dir.search_by_dn(phys_dn):
                print "%sAPIC: Physical Domain '%s' for EPG '%s'" % (self.alert, epg['physical-domain'], epg_dn)
                validation_result = False
        if 'vmm-domains' in epg.keys():
            for vmm_domain in epg['vmm-domains']:
                vmm_dn = '%s/rsdomAtt-[uni/vmmp-VMware/dom-%s]' % (epg_dn, vmm_domain)
                if not self.mo_dir.search_by_dn(vmm_dn):
                    print "%sAPIC: VMM Domain '%s' for EPG '%s'" % (self.alert, vmm_domain, epg_dn)
                    validation_result = False
        if 'l2-domain' in epg.keys():
            l2_dom_dn = '%s/rsdomAtt-[uni/l2dom-%s]' % (epg_dn, epg['l2-domain'])
            if not self.mo_dir.search_by_dn(l2_dom_dn):
                print "%sAPIC: L2 Domain '%s' for EPG '%s'" % (self.alert, epg['l2-domain'], epg_dn)
                validation_result = False
        if 'static-paths' in epg.keys():
            for path in epg['static-paths']:
                path_dn = "%s/rspathAtt-[topology/pod-1/protpaths-%s/pathep-[%s]]" % (
                epg_dn, path['name'], path['polgrp'])
                if not self.mo_dir.search_by_dn(path_dn):
                    print "%sAPIC: Static path '%s' polgrp '%s' for EPG '%s'" % (
                    self.alert, path['name'], path['polgrp'], epg_dn)
                    validation_result = False
        if 'contracts' in epg.keys():
            if 'provide' in epg['contracts'].keys():
                if epg['contracts']['provide']:
                    apic_epg_provided_contracts = self.mo_dir.search_for_children(epg_dn, 'fvRsProv', 'tnVzBrCPName')
                    for contract in epg['contracts']['provide']:
                        if isinstance(contract, dict):
                            contract = contract['name']
                        if contract not in apic_epg_provided_contracts:
                            print "%sAPIC: Provide Contract '%s' for EPG '%s'" % (self.alert, contract, epg_dn)
                            validation_result = False
            if 'consume' in epg['contracts'].keys():
                if epg['contracts']['consume']:
                    apic_epg_consumed_contracts = self.mo_dir.search_for_children(epg_dn, 'fvRsCons', 'tnVzBrCPName')
                    for contract in epg['contracts']['consume']:
                        if isinstance(contract, dict):
                            contract = contract['name']
                        if contract not in apic_epg_consumed_contracts:
                            print "%sAPIC: Consume Contract '%s' for EPG '%s'" % (self.alert, contract, epg_dn)
                            validation_result = False
            if 'consume-imported' in epg['contracts'].keys():
                if epg['contracts']['consume-imported']:
                    for contract in epg['contracts']['consume-imported']:
                        tenant_dn = epg_dn.split('/ap-')[0]
                        if isinstance(contract, dict):
                            contract = contract['name']
                        if contract not in imported_contracts:
                            imported_contracts.append(contract)
                        # if not mo_dir_login.search_by_dn('%s/cif-%s' % (tenant_dn, contract)):
                        #     tenant_name = tenant_dn.split('/')[1].split('tn-')[1]
                        #     print "%sAPIC: Imported contract '%s' in tenant '%s'" % (alert, contract, tenant_name)
                        #     validation_result = False
                        if not self.mo_dir.search_by_dn('%s/rsconsIf-%s' % (epg_dn, contract)):
                            print "%sAPIC: Consume Contract Interface '%s' for EPG '%s'" % (self.alert, contract,
                                                                                            epg_dn)
                            validation_result = False
    
        # # Check to see if the imported Contracts in the EPG's have been imported into this Tenant
        # if imported_contracts:
        #     missing_imported_contract =False
        #     tenant_dn = app_profile_dn.split('/ap-')[0]
        #     for contract in imported_contracts:
        #         if not mo_dir_login.search_by_dn('%s/cif-%s' % (tenant_dn, contract)):
        #             tenant_name = tenant_dn.split('/')[1].split('tn-')[1]
        #             print "Missing on APIC: Imported contract '%s' in tenant '%s'" % (contract, tenant_name)
        #             missing_imported_contract = True
        #     if missing_imported_contract:
        #         print "INFO: More informtaion needed to correct the above Imported contract"
    
        # Return result
        return validation_result


class Process:
    def __init__(self, mo_dir, alert_message, report_only=False, delete_on_apic=False, verbose=False):
        self.mo_dir = mo_dir
        self.report_only = report_only
        self.verbose = verbose
        self.create = Create(mo_dir)
        self.validate = Validate(mo_dir, self.create, alert_message, report_only, delete_on_apic)
        self.alert = alert_message
        self.delete_on_apic = delete_on_apic
        
    # Process filter
    def filter(self, tenant_name, f):
        filter_dn = 'uni/tn-%s/flt-%s' % (tenant_name, f['name'])
    
        if self.verbose:
            print 'Verifying filter "%s"' % filter_dn
    
        # Check if filter MO exists on APIC
        if not self.mo_dir.search_by_dn(filter_dn):
            print "%sAPIC: Filter '%s'" % (self.alert, filter_dn)
    
            # Create filter
            if not self.report_only:
                self.create.filter(tenant_name, f)
        # Check filter
        else:
            apic_entry_list = self.mo_dir.search_for_children(filter_dn, 'vzEntry', 'name')
            # Verify each YAML entry against APIC
            for entry in f['entries']:
    
                # Check if entry exists
                entry_dn = '%s/e-%s' % (filter_dn, entry['name'])
                if self.verbose:
                    print 'Searching for "%s" on APIC' % entry_dn
                if entry['name'] not in apic_entry_list:
                    print "%sAPIC: Filter entry '%s'" % (self.alert, entry_dn)
    
                    # Create entry
                    if not self.report_only:
                        self.create.entry(filter_dn, entry)
    
                # Validate entry
                else:
                    if self.verbose:
                        print "PASS: Filter entry '%s' found on APIC" % entry_dn
                        print "Validating filter entry '%s' matched YAML" % entry_dn
    
                    if not self.validate.entry(entry, entry_dn):
                        if self.verbose:
                            print "FAIL: Correcting Filter entry '%s'" % entry_dn
                        if not self.report_only:
                            self.create.entry(filter_dn, entry)
                    # Pass
                    else:
                        if self.verbose:
                            print "PASS: Filter entry '%s' is correct" % entry_dn
    
            # Look for extra entries on APIC that aren't in YAML
            yaml_entry_list = []
            for entry in f['entries']:
                yaml_entry_list.append(entry['name'])
            for e in apic_entry_list:
                if e not in yaml_entry_list:
                    entry_dn = '%s/e-%s' % (filter_dn, e)
                    if self.report_only:
                        print "%sYAML: Entry '%s'" % (self.alert, entry_dn)
                    # Delete filter entry
                    if self.delete_on_apic and not self.report_only:
                        print "FIX: Deleting filter entry '%s' from APIC" % entry_dn
                        self.create.delete_mo(entry_dn)
                    # elif report_only: # TESTING NEW REPORT
                    #     fail_message = alert + 'YAML\n'
                    #     for line in entry_dn.split('/')[1:]:
                    #         if line.startswith('tn-'):
                    #             fail_message += "    Tenant: '%s'" % line[3:]
                    #         elif line.startswith('flt-'):
                    #             fail_message += "\n    Filter: '%s'" % line[4:]
                    #         elif line.startswith('e-'):
                    #             apic_entry = line[2:]
                    #     print fail_message+"\n  > Filter Entry: '%s'" % e

    # Process contract
    def contract(self, tenant_name, contract):
        """

        :param tenant_name:
        :param contract:
        :return:
        """
        contract_dn = 'uni/tn-%s/brc-%s' % (tenant_name, contract['name'])
    
        if self.verbose:
            print 'Verifying contract "%s"' % contract_dn
    
        # Check if filter MO exists on APIC
        if self.verbose:
            print 'Searching for contract "%s" on APIC' % contract_dn
    
        if not self.mo_dir.search_by_dn(contract_dn):
            print "%sAPIC: Contract '%s'" % (self.alert, contract_dn)
    
            # Create the contract
            if not self.report_only:
                self.create.contract(tenant_name, contract)
    
        # Validate contract
        else:
            # Check scope
            apic_contract = self.mo_dir.search_by_dn(contract_dn)
            if self.verbose:
                print "Checking scope of contract '%s'" % contract_dn
            if not apic_contract.scope == contract['scope']:
                print "Mismatch in '%s': YAML[scope]='%s' | APIC[scope]='%s" % (contract_dn, contract['scope'],
                                                                                apic_contract.scope)
    
                # Push update to make APIC match YAML
                if not self.report_only:
                    print "%sAPIC to correct contract scope: '%s'" % (self.alert, contract_dn)
                    self.create.contract(tenant_name, contract)
    
            # Validate subjects
            apic_subject_list = self.mo_dir.search_for_children(contract_dn, 'vzSubj', 'name')
            for subject in contract['subjects']:
    
                subject_dn = '%s/subj-%s' % (contract_dn, subject['name'])
    
                # Check if subject exists
                if self.verbose:
                    print "Searching for contract subject '%s' on APIC" % subject_dn
                if subject['name'] not in apic_subject_list:
                    print "%sAPIC: Contract subject '%s'" % (self.alert, subject_dn)
    
                    # Create the subject
                    if not self.report_only:
                        self.create.subject(contract_dn, subject)
                # Validate subject
                else:
                    if self.verbose:
                        print "PASS: Found contract subject '%s' on APIC" % subject_dn
                        print "Validating contract subject '%s' on APIC" % subject_dn
    
                    if not self.validate.subject(subject_dn, subject):
                        if not self.report_only:
                            print "%sAPIC: Contract subject '%s'" % (self.alert, subject_dn)
                            self.create.subject(contract_dn, subject)
    
                    else:
                        if self.verbose:
                            print "PASS: Contract subject '%s' has been validated" % subject_dn

    # Process routed external network
    def l3out(self, tenant_name, l3out):
        """

        :param tenant_name:
        :param l3out:
        :return:
        """
    
        l3out_dn = 'uni/tn-%s/out-%s' % (tenant_name, l3out['name'])
    
        # Search for l3out
        if self.verbose:
            print "Searching for routed external network '%s' on APIC" % l3out_dn
        if not self.mo_dir.search_by_dn(l3out_dn):
            print "%sAPIC: External Routed Network '%s'" % (self.alert, l3out_dn)
    
            # Create routed external network
            if not self.report_only:
                self.create.l3out(tenant_name, l3out)
        # Check external networks
        else:
            apic_external_network = self.mo_dir.search_for_children(l3out_dn, 'l3extInstP', 'name')
            # Delete External Networks not found in the YAML file
            yaml_l3out_list = []
            for line in l3out['external-networks']:
                yaml_l3out_list.append(line['name'])
            for ext_network in apic_external_network:
                if ext_network not in yaml_l3out_list:
                    if self.report_only:
                        print "%sYAML: External network instance '%s' in '%s'" % (self.alert, ext_network, l3out_dn)
                        if self.delete_on_apic:
                            self.create.delete_mo('%s/instP-%s' % (l3out_dn, ext_network))
    
            for ext_net in l3out['external-networks']:
                ext_net_dn = '%s/instP-%s' % (l3out_dn, ext_net['name'])
    
                # Search for external network
                if self.verbose:
                    print "Searching for external network '%s' on APIC" % ext_net_dn
                if ext_net['name'] not in apic_external_network:
                    print "%sAPIC: External network instance '%s' in '%s'" % (self.alert, ext_net['name'], l3out_dn)
    
                    # Create external network
                    if not self.report_only:
                        self.create.ext_net(l3out_dn, ext_net)
    
                # Validate externet network
                else:
    
                    # Network ranges
                    if 'range' in ext_net.keys():
                        self.validate.ip_nets(ext_net, ext_net_dn, l3out_dn)
    
                    # Contracts
                    if 'contracts' in ext_net.keys():
                        if self.verbose:
                            print "Validating provided contracts for '%s'" % ext_net_dn
                        if not self.validate.ext_net_contracts(ext_net_dn, ext_net['contracts']):
                            if not self.report_only:
                                self.create.ext_net(l3out_dn, ext_net)
                                # if self.delete_on_apic:
                                #     apic_provided_contracts = mo_dir_login.search_for_children(ext_net_dn, 'fvRsProv',
                                #                                                                'tnVzBrCPName')
                                #     for p in apic_provided_contracts:
                                #         if p not in contracts['provide']:
                                #           print alert + 'Provided contract "%s" for "%s" on APIC, but not in YAML' % \
                                #                           (p, ext_net_dn)
    
    # Process VRF level contracts
    def vrf(self, tenant_name, vrf):
        """

        :param tenant_name:
        :param vrf:
        :return:
        """
    
        vrf_dn = 'uni/tn-%s/ctx-%s' % (tenant_name, vrf['name'])
    
        # Search for VRF
        if self.verbose:
            print "Searching for VRF '%s' on APIC" % vrf_dn
        if not self.mo_dir.search_by_dn(vrf_dn):
            print "%sAPIC: VRF '%s' in Tenant '%s'" % (self.alert, vrf['name'], tenant_name)
            if not self.report_only:
                top_mo = cobra.model.pol.Uni('')
                fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)
                fv_ctx = cobra.model.fv.Ctx(fv_tenant, name=vrf['name'])
                self.mo_dir.commit(fv_tenant, 'VRF')
                self.vrf_contracts(vrf_dn, vrf, fv_ctx)
    
            else:
                return
        else:
            self.vrf_contracts(vrf_dn, vrf, self.report_only)
    
    def vrf_contracts(self, vrf_dn, vrf, vrf_mo=False):
        """

        :param vrf_dn:
        :param vrf:
        :param vrf_mo:
        :return:
        """
    
        # Provided contracts
        if 'provide' in vrf['contracts'].keys():
            apic_list = self.mo_dir.search_for_children(vrf_dn+'/any', 'vzRsAnyToProv', 'tnVzBrCPName')
            for p in vrf['contracts']['provide']:
                if p not in apic_list:
                    print "%sAPIC: Provide contract '%s' for VRF '%s'" % (self.alert, p, vrf_dn)
                    if not self.report_only:
                        self.create.vrf_prov_contract(vrf_dn, p, vrf_mo)
            if self.report_only or self.delete_on_apic:
                for p in apic_list:
                    if p not in vrf['contracts']['provide']:
                        if self.report_only:
                            print "%sYAML: Provide contract '%s' for VRF '%s'" % (self.alert, p, vrf_dn)
                        elif self.delete_on_apic:
                            print "Removing Provide contract '%s' from VRF '%s'" % (p, vrf_dn)
                            prov_dn = '%s/rsanyToProv-%s' % (vrf_dn+'/any', p)
                            self.create.delete_mo(prov_dn)
    
        # Consumed contracts
        if 'consume' in vrf['contracts'].keys():
            apic_list = self.mo_dir.search_for_children(vrf_dn+'/any', 'vzRsAnyToCons', 'tnVzBrCPName')
            for c in vrf['contracts']['consume']:
                if c not in apic_list:
                    print "%sAPIC: Consume contract '%s' for VRF '%s'" % (self.alert, c, vrf_dn)
                    if not self.report_only:
                        self.create.vrf_cons_contract(vrf_dn, c, vrf_mo)
            if self.report_only or self.delete_on_apic:
                for c in apic_list:
                    if c not in vrf['contracts']['consume']:
                        if self.report_only:
                            print "%sYAML: Consume contract '%s' for VRF '%s'" % (self.alert, p, vrf_dn)
                        elif self.delete_on_apic:
                            print "Removing: Consume contract '%s' for VRF '%s'" % (p, vrf_dn)
                            cons_dn = '%s/rsanyToCons-%s' % (vrf_dn+'/any', c)
                            self.create.delete_mo(cons_dn)
    
    def bridge_domain(self, tenant_name, bridge_domain):
        """

        :param tenant_name:
        :param bridge_domain:
        :return:
        """
        bridge_domain_dn = 'uni/tn-%s/BD-%s' % (tenant_name, bridge_domain['name'])
    
        if self.verbose:
            print "Verifying Bridge Domain '%s'" % bridge_domain_dn

        # Check if Bridge Domain MO exists on APIC
        if self.verbose:
            print "Searching for Bridge Domain '%s' on APIC" % bridge_domain_dn
        if not self.mo_dir.search_by_dn(bridge_domain_dn):
            # Create the Bridge Domain
            print "%sAPIC: Bridge Domain '%s'" % (self.alert, bridge_domain_dn)
            if not self.report_only:
                self.create.bridge_domain(tenant_name, bridge_domain, bridge_domain_dn)
        # Validate Bridge Domain
        else:
            if not self.validate.bridge_domain(bridge_domain, bridge_domain_dn):
                if not self.report_only:
                    self.create.bridge_domain(tenant_name, bridge_domain, bridge_domain_dn)

    def epg(self, tenant_name, app_profile, app_profile_dn):
        """

        :param tenant_name:
        :param app_profile_dn:
        :param app_profile:
        :return:
        """
    
        for epg in app_profile['epgs']:
            epg_dn = '%s/epg-%s' % (app_profile_dn, epg['name'])
    
            if not self.mo_dir.search_by_dn(epg_dn):
                print "%sAPIC: EPG '%s' in '%s'" % (self.alert, epg['name'], epg_dn)
                if not self.report_only:
                    self.create.epg(tenant_name, epg, app_profile['name'])
            elif not self.validate.epg(epg, app_profile_dn):
                if not self.report_only:
                    self.create.epg(tenant_name, epg, app_profile['name'])
    
    
def main(arguments):

    # Create a login session
    if arguments.yaml_to_xml:
        mo_dir_login = ApicSession(None, None, None, False)
        mo_dir_login.yaml_to_xml = True
        mo_dir_login.change_made = True
    else:
        mo_dir_login = ApicSession(arguments.apic, arguments.username, arguments.password, arguments.test_only)
        mo_dir_login.login()

    if arguments.yaml_to_xml or arguments.show_xml:
        arguments.report_only = False
        alert_message = '\nXML output for '
        if arguments.show_xml:
            mo_dir_login.show_xml = True
    elif arguments.report_only:
        mo_dir_login.change_made = True
        alert_message = 'Not found on '
    else:
        alert_message = '\nPushing to '

    process = Process(mo_dir_login, alert_message, arguments.report_only, arguments.delete_on_apic, arguments.verbose)

    yaml_code = process.validate.yaml(arguments.input_file)

    # Process each tenant
    for tenant in yaml_code['tenants']:
        if arguments.verbose:
            print 'Processing tenant "%s" ' % tenant['name']

        # Check tenant exists
        tenant_dn = 'uni/tn-%s' % tenant['name']
        if not mo_dir_login.search_by_dn(tenant_dn):
            print "%sAPIC: Tenant '%s'" % (alert_message, tenant['name'])
            # Create tenant
            if not arguments.report_only:
                process.create.tenant(tenant['name'])
            else:
                continue

        # Filters
        if 'filters' in tenant.keys():
            if arguments.verbose:
                print 'Processing filters'

            # Process each filter
            for f in tenant['filters']:
                process.filter(tenant['name'], f)

        # Contracts
        if 'contracts' in tenant.keys():
            if arguments.verbose:
                print '\nProcessing contracts'

            # Process each contract
            for contract in tenant['contracts']:
                process.contract(tenant['name'], contract)

        # Routed external networks
        if 'l3Outs' in tenant.keys():
            if arguments.verbose:
                print '\nProcessing routed external networks'

            # Process each l3out
            for l3out in tenant['l3Outs']:
                process.l3out(tenant['name'], l3out)

        # VRF level contracts
        if 'vrfs' in tenant.keys():
            if arguments.verbose:
                print '\nProcessing VRF level contracts'

            # Process each VRF
            for vrf in tenant['vrfs']:
                process.vrf(tenant['name'], vrf)

        # Bridge Domains
        if 'bridge-domains' in tenant.keys():
            if arguments.verbose:
                print '\nProcessing Bridge Domains'

            # Process each Bridge Domain
            for bride_domain in tenant['bridge-domains']:
                process.bridge_domain(tenant['name'], bride_domain)

        if 'app-profiles' in tenant.keys():
            if arguments.verbose:
                print '\nProcessing Application Profiles'

            # Process each Application Profile
            for app_profile in tenant['app-profiles']:
                app_profile_dn = 'uni/tn-%s/ap-%s' % (tenant['name'], app_profile['name'])

                # Check if Application Profile MO exists on APIC
                if arguments.verbose:
                    print "Searching for Application Profile '%s' on APIC" % app_profile_dn
                if not mo_dir_login.search_by_dn(app_profile_dn):

                    # Create the Application Profile
                    print "%sAPIC: Application Profile '%s'" % (alert_message, app_profile_dn)
                    if not arguments.report_only:
                        process.create.app_profile(tenant['name'], app_profile)
                    else:
                        continue

                if 'epgs' in app_profile.keys():
                    process.epg(tenant['name'], app_profile,  app_profile_dn)

    mo_dir_login.mo_dir.logout()
    return mo_dir_login.change_made

if __name__ == '__main__':
    # Read in the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--apic", help="APIC IP address or hostname")
    parser.add_argument("-u", "--username", help="APIC Username")
    parser.add_argument("-p", "--password", help="APIC Password")
    parser.add_argument("-f", "--input_file", help="Input YAML File")
    parser.add_argument("-t",
                        "--test_only",
                        help="Simulate policy being pushed to APIC",
                        required=False,
                        action='store_true')
    parser.add_argument("-x",
                        "--show_xml",
                        help="Do not push config but show xml output",
                        required=False,
                        action='store_true')
    parser.add_argument("-r",
                        "--report_only",
                        help="Do not push config, report only",
                        required=False,
                        action='store_true')
    parser.add_argument("-y2x",
                        "--yaml_to_xml",
                        help="Convert YAML input file to XML",
                        required=False,
                        action='store_true')
    parser.add_argument("-c",
                        "--abcconnect",
                        help="Use credentials from abcconnect",
                        required=False,
                        action='store_true')
    parser.add_argument("-v",
                        "--verbose",
                        help="Verbose output",
                        required=False,
                        action='store_true')
    parser.add_argument("-V",
                        "--version",
                        help="Print script versoin number",
                        required=False,
                        action='store_true')

    # parser.add_argument("-d",
    #                     "--delete_on_apic",
    #                     help="Delete policy found on APIC that is not in the YAML file",
    #                     required=False,
    #                     action='store_true')

    args = parser.parse_args()
    args.delete_on_apic = False

    if args.version:
        print '\nVersion:', version
        print
        sys.exit()

    # Interactive mode if required
    if not args.input_file:
        args.input_file = raw_input("Input Filename: ")
    if not args.yaml_to_xml:
        if not args.apic:
            args.apic = raw_input("APIC Address: ")
        if args.abcconnect:

            from abcconnect import ConnectCfg
            cfg = ConnectCfg()
            args.username = cfg.user
            args.password = cfg.password
        if not args.username:
            args.username = raw_input("APIC Username: ")
        if not args.password:
            args.password = getpass.getpass("APIC Password: ")
        if args.delete_on_apic:
            while True:
                yes_or_no = raw_input("\nYou have enabled the DELETE option, do you wish to continue? (y/n):").upper()
                if yes_or_no == "Y":
                    break
                elif yes_or_no == "N":
                    exit()

    # Validate YAML file format
    if args.verbose:
        print '\nValidating YAML format of input file...'

    if not main(args):
        print '\nYAML and APIC policy match so no changes made.\n'
