
import cobra.mit.access
import cobra.mit.session
import cobra.mit.request
import cobra.mit.naming
import cobra.model.infra
import cobra.model.fabric
import cobra.model.mgmt
import cobra.model.fv
import cobra.model.fvns
import cobra.model.pol
import cobra.model.psu
import cobra.model.datetime
import cobra.model.comm
import cobra.model.dns
import cobra.model.file
import cobra.model.syslog
import cobra.model.fabric
import cobra.model.cdp
import cobra.model.lldp
import cobra.model.lacp
import cobra.model.stp
import cobra.model.lbp
import cobra.model.vz
import cobra.model.phys
import cobra.model.dhcp
import cobra.model.l3ext
import cobra.model.aaa

from cobra.internal.codec.xmlcodec import toXMLStr
from socket import gaierror, gethostbyname, gethostbyaddr

__author__ = 'developer'

""" General Functions """


def host_dns(name, return_ip=False):
    """Used to check if device name entered is a cname or real name
        can be used to return IP address as well

    :param name:
    :param return_ip:
    :return:
    """
    try:
        ip = gethostbyname(name)

        if return_ip:
            return ip
        else:
            real_name = gethostbyaddr(ip)[0]
            if real_name.find('.abc.com') > 0:
                return real_name.split('.abc.com')[0]
            else:
                raise SystemError('%s not part of abc.com' % name)

    except gaierror:
        raise SystemError('%s not found in DNS' % name)


def apic_login(apic, user, password):
    """

    :param apic:
    :param user:
    :param password:
    :return:
    """

    ls = cobra.mit.session.LoginSession('https://' + apic, user, password)
    md = cobra.mit.access.MoDirectory(ls)
    md.login()

    print("Logged into %s" % apic)
    return md


def apic_commit(md, top_mo, debug):
    """ Used to commit the changes to the APIC
    :param md: The Model Directory created from the login information
    :param top_mo: the built-up module object
    :param debug: if debuging is on or off
    :return:
    """

    if debug:
        print(toXMLStr(top_mo))
    c = cobra.mit.request.ConfigRequest()
    c.addMo(top_mo)
    md.commit(c)


""" Fabric Basic Config """


def set_bgp_policy(md, site_as, rr_nodes, debug=False):
    """
    :param md:
    :param site_as: Fabric BGP AS number
    :param rr_nodes: list of route reflector nodes
    :param debug:
    :return:
    """
    node_id = 0

    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/bgpInstP-default')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    bgp_inst_pol = cobra.model.bgp.InstPol(top_mo, ownerKey='', name='default', descr='', ownerTag='')
    bgp_rrp = cobra.model.bgp.RRP(bgp_inst_pol, descr='')

    for node in rr_nodes:
        if node_id == 0:
            bgp_rrnode_pe_p = cobra.model.bgp.RRNodePEp(bgp_rrp, descr='', id='%s' % node)
            node_id = 1
        elif node_id == 1:
            bgp_rrnode_pe_p2 = cobra.model.bgp.RRNodePEp(bgp_rrp, descr='', id='%s' % node)

    bgp_as_p = cobra.model.bgp.AsP(bgp_inst_pol, descr='', asn='%s' % site_as)

    apic_commit(md, top_mo, debug)


def create_poddefault_policy(md, debug=False):
    """ Used to create the default pod-policy and set bgp to default
    :param md:
    :param debug:
    :return:
    """

    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/funcprof/podpgrp-Pod-Policy-Default')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    fabric_pod_pgrp = cobra.model.fabric.PodPGrp(top_mo, ownerKey='', name='Pod-Policy-Default', descr='', ownerTag='')
    fabric_rs_pod_pgrp_bgp_rrp = cobra.model.fabric.RsPodPGrpBGPRRP(fabric_pod_pgrp, tnBgpInstPolName='default')

    apic_commit(md, top_mo, debug)

    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/podprof-default/pods-default-typ-ALL')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    fabric_pods = cobra.model.fabric.PodS(top_mo, ownerKey='', name='default', descr='', ownerTag='', type='ALL')
    fabric_rs_pod_pgrp = cobra.model.fabric.RsPodPGrp(fabric_pods, tDn='uni/fabric/funcprof/podpgrp-Pod-Policy-Default')

    apic_commit(md, top_mo, debug)


def create_generic_vrf(md, vrf_name, debug=False):
    """ Used to create a generic vrf with default provide/consume contracts

    :param md:
    :param vrf_name: Name that you want the vrf to be called (no spaces)
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-common/ctx-%s' % vrf_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    fv_ctx = cobra.model.fv.Ctx(top_mo, name='%s' % vrf_name)
    vz_any = cobra.model.vz.Any(fv_ctx, matchT='AtleastOne')
    vz_rs_any_to_prov = cobra.model.vz.RsAnyToProv(vz_any, tnVzBrCPName='default', matchT='AtleastOne',
                                                   prio='unspecified')
    vz_rs_any_to_cons = cobra.model.vz.RsAnyToCons(vz_any, tnVzBrCPName='default', prio='unspecified')

    apic_commit(md, top_mo, debug)


def set_fabric_balancer(md, dyn_lb_mode, lb_mode, debug=False):
    """ Used to set the Load Balancer Policy Default
    :param md:
    :param dyn_lb_mode: Dynamic Load Balancing Mode (Conservative, Aggressive, Off)
    :param lb_mode: Load Balancing Mode (Traditional, Link Failure Resiliance)
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/lbp-default')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    lbp_pol = cobra.model.lbp.Pol(top_mo, ownerKey='', name='default', descr='', dlbMode=dyn_lb_mode, pri='off',
                                  mode=lb_mode, ownerTag='')

    apic_commit(md, top_mo, debug)


def set_power_redundancy(md, pol_name, pol_mode, debug=False):
    """Used to set the redundancy mode of the power supplies in the switches

    :param md: The Model Directory created from the login information
    :param mode: rdn = redundant, comb = combined, insrc-rdn = input source redundancy, n-rdn = non-redundant
                 ps-rdn = Power Output Redundancy, sinin-rdn = Single Input redundancy
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/psuInstP-default')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    psu_inst_pol = cobra.model.psu.InstPol(top_mo, adminRdnM=pol_mode, name=pol_name)

    apic_commit(md, top_mo, debug)


def set_datetime_format(md, site_tz, offset_state, display_format, debug=False):
    """

    :param md:
    :param site_tz: RTP = n240_America-New_York, Dallas = n300_America-Chicago,
                    SJ = n420_America-Los_Angeles
    :param offset_state: enabled or disabled
    :param display_format: utc or local
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/format-default')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    datetime_format = cobra.model.datetime.Format(top_mo, name='default', tz=site_tz,
                                                  showOffset=offset_state, displayFormat=display_format)

    apic_commit(md, top_mo, debug)


def set_ntp_server(md, ntp_srv, epg, debug=False, prefer='false'):
    """Provision NTP server sources

    :param md:
    :param ntp_srv: NTP Server IP or Hostname
    :param prefer: true / false
    :param epg: 'uni/tn-mgmt/mgmtp-default/oob-default'
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/time-default/ntpprov-%s' % ntp_srv)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    datetime_ntp_prov = cobra.model.datetime.NtpProv(top_mo, name=ntp_srv, preferred=prefer)
    datetime_rs_ntp_prov_to_epg = cobra.model.datetime.RsNtpProvToEpg(datetime_ntp_prov, tDn=epg)

    apic_commit(md, top_mo, debug)


def set_http_redirect(md, state, debug=False):
    """

    :param md:
    :param debug:
    :param state:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/comm-default/http')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    comm_http = cobra.model.comm.Http(top_mo, redirectSt=state)

    apic_commit(md, top_mo, debug)


def set_dns_srv(md, dns_srv, debug=False, prefer='false'):
    """

    :param md:
    :param dns_srv:
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/dnsp-default/prov-[%s]' % dns_srv)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    dns_prov = cobra.model.dns.Prov(top_mo, addr=dns_srv, preferred=prefer)

    apic_commit(md, top_mo, debug)


def set_dns_domain(md, domain, epg, debug=False, prefer='false'):
    """

    :param md:
    :param domain: search domain
    :param epg: 'uni/tn-mgmt/mgmtp-default/oob-default'
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/dnsp-default/dom-%s' % domain)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    dns_domain = cobra.model.dns.Domain(top_mo, name=domain, isDefault=prefer)
    dns_rs_profile_to_epg = cobra.model.dns.RsProfileToEpg(top_mo, tDn=epg)

    apic_commit(md, top_mo, debug)


def set_oob_dnslbl(md, label_name, debug):
    """
    Used to set the DNS label for use on the Switches
    :param md:
    :param label_name: default - currently only think that is accepted
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-mgmt/ctx-oob/dnslbl-default')
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    dns_lbl = cobra.model.dns.Lbl(top_mo, ownerKey='', name=label_name, descr='', tag='yellow-green', ownerTag='')

    apic_commit(md, top_mo, debug)


def set_syslog(md, grp_name, level, events_inc, dest_grp_name, servers, epg, debug=False):
    """
        data to be sent: servername:serverip:severity
    :param md:
    :param servers: List of servers and there severity
    :param epg:
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/slgroup-%s' % grp_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    syslog_group = cobra.model.syslog.Group(top_mo, name=dest_grp_name)
    syslog_console = cobra.model.syslog.Console(syslog_group, adminState='disabled')
    syslog_file = cobra.model.syslog.File(syslog_group, severity='debugging')
    syslog_prof = cobra.model.syslog.Prof(syslog_group)
    syslog_remote_dest = cobra.model.syslog.RemoteDest(syslog_group, name='ees-bxb', host='161.44.124.119',
                                                       severity='information')
    file_rs_aremote_host_to_epg = cobra.model.file.RsARemoteHostToEpg(syslog_remote_dest, tDn=epg)
    syslog_remote_dest2 = cobra.model.syslog.RemoteDest(syslog_group, name='rcdn-splunk-fwd-01', host='173.37.108.25',
                                                        severity='debugging')
    file_rs_aremote_host_to_epg2 = cobra.model.file.RsARemoteHostToEpg(syslog_remote_dest2, tDn=epg)
    syslog_remote_dest3 = cobra.model.syslog.RemoteDest(syslog_group, name='ees-rtp', host='64.102.6.250',
                                                        severity='information')
    file_rs_aremote_host_to_epg3 = cobra.model.file.RsARemoteHostToEpg(syslog_remote_dest3, tDn=epg)

    apic_commit(md, top_mo, debug)

    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/moncommon/slsrc-%s' % grp_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    syslog_src = cobra.model.syslog.Src(top_mo, name=grp_name, minSev=level, incl=events_inc)
    syslog_rs_dest_group = cobra.model.syslog.RsDestGroup(syslog_src, tDn='uni/fabric/slgroup-%s' % dest_grp_name)

    apic_commit(md, top_mo, debug)


def create_interface_pol(md, pol_name, speed, auto_neg, link_debounce=100, debug=False):
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/hintfpol-%s' % pol_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    fabric_hif_pol = cobra.model.fabric.HIfPol(top_mo, ownerKey='', name=pol_name, descr='', ownerTag='',
                                               autoNeg=auto_neg, speed=speed, linkDebounce=link_debounce)

    apic_commit(md, top_mo, debug)


def create_cdp_pol(md, pol_name, admin_state, debug=False):
    """

    :param md:
    :param pol_name:
    :param admin_state:
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/cdpIfP-%s' % pol_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    cdp_if_pol = cobra.model.cdp.IfPol(top_mo, ownerKey='', name=pol_name, descr='', adminSt=admin_state, ownerTag='')

    apic_commit(md, top_mo, debug)


def create_lldp_pol(md, pol_name, rx_state, tx_state, debug=False):
    """

    :param md:
    :param pol_name:
    :param rx_state:
    :param tx_state:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/lldpIfP-%s' % pol_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    lldp_if_pol = cobra.model.lldp.IfPol(top_mo, ownerKey='', name=pol_name, descr='', adminTxSt=tx_state,
                                         adminRxSt=rx_state, ownerTag='')

    apic_commit(md, top_mo, debug)


def create_lacp_pol(md, pol_name, min_links, max_links, ctrl, mode, debug=False):
    """

    :param md:
    :param pol_name:
    :param min_links:
    :param max_links:
    :param ctrl: 'fast-sel-hot-stdby,graceful-conv,susp-individual,load-defer'
    :param mode:
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/lacplagp-%s' % pol_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    lacp_lag_pol = cobra.model.lacp.LagPol(top_mo, ownerKey='', name=pol_name, descr='', minLinks=min_links,
                                           ctrl=ctrl, maxLinks=max_links, mode=mode, ownerTag='')

    apic_commit(md, top_mo, debug)


def create_stp_pol(md, pol_name, ctrl, debug=False):
    """

    :param md:
    :param pol_name:
    :param ctrl: Choices are bpdu-filter, bpdu-guard
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/ifPol-%s' % pol_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    stp_if_pol = cobra.model.stp.IfPol(top_mo, ownerKey='', name=pol_name, descr='', ctrl=ctrl, ownerTag='')

    apic_commit(md, top_mo, debug)


def create_aep_prfl(md, prfl_name, infra_enable, phys_dom, infra_vlan=False, debug=False):
    """

    :param md:
    :param prf_name:
    :param debug:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/attentp-%s' % prfl_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    infra_att_entity_p = cobra.model.infra.AttEntityP(top_mo, ownerKey='', name=prfl_name, descr='', ownerTag='')
    if phys_dom:
        infra_rs_dom_p = cobra.model.infra.RsDomP(infra_att_entity_p, tDn='uni/phys-%s' % phys_dom)

    if infra_enable:
        infra_prov_acc = cobra.model.infra.ProvAcc(infra_att_entity_p, name='provacc', descr='')
        dhcp_infra_prov_p = cobra.model.dhcp.InfraProvP(infra_prov_acc, mode='controller', descr='', name='')
        infra_rs_func_to_epg = cobra.model.infra.RsFuncToEpg(infra_prov_acc, tDn='uni/tn-infra/ap-access/epg-default',
                                                             encap='vlan-%s' % infra_vlan)

    if 'ucsStnd' in prfl_name:
        infra_att_policy_group = cobra.model.infra.AttPolicyGroup(infra_att_entity_p, name='', descr='')
        infra_rs_override_lacp_pol = cobra.model.infra.RsOverrideLacpPol(infra_att_policy_group,
                                                                         tnLacpLagPolName='lacpMacPin-IfPol')

    apic_commit(md, top_mo, debug)


def create_physdom(md, physdom_name, pool_name, pool_type, debug=False):
    """
    :param md:
    :param physdom_name:
    :param debug:
    :return:
    """
    top_mo = cobra.model.pol.Uni('')

    phys_dom_p = cobra.model.phys.DomP(top_mo, ownerKey='', name=physdom_name, ownerTag='')
    # infra_rt_dom_p = cobra.model.infra.RtDomP(phys_dom_p, tDn="uni/infra/attentp-%s" % aep_prfl)
    infra_rs_vlan_ns = cobra.model.infra.RsVlanNs(phys_dom_p, tDn='uni/infra/vlanns-[%s]-%s' % (pool_name, pool_type))

    apic_commit(md, phys_dom_p, debug)


def create_vlan_pool(md, pool_name, pool_type, vlan_from, vlan_to, physdom_name, debug=False):
    """
    :param md:
    :param pool_name:
    :param pool_type:
    :param vlan_from:
    :param vlan_to:
    :param physdom_name:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/vlanns-[%s]-%s' % (pool_name, pool_type))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    fvns_vlan_inst_p = cobra.model.fvns.VlanInstP(top_mo, ownerKey='', name=pool_name, descr='', ownerTag='',
                                                  allocMode=pool_type)
    fvns_encap_blk = cobra.model.fvns.EncapBlk(fvns_vlan_inst_p, from_=vlan_from, name='', descr='', to=vlan_to)

    apic_commit(md, top_mo, debug)


""" Switch Management Functions """


def create_switch_profile(md, prf_name, node_ids, debug=False):
    """

    :param md:
    :param prf_name:
    :param node_ids:
    :param debug:
    :return:
    """

    if type(node_ids) == int:
        node1 = node_ids
    elif type(node_ids) == list:
        node1 = node_ids[0]
    else:
        raise SystemError("Invalid node numbers please check config")

    name_leaf1 = "sw" + str(node1)
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/nprof-%s' % prf_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    infra_node_p = cobra.model.infra.NodeP(top_mo, name=prf_name)
    infra_leaf_s = cobra.model.infra.LeafS(infra_node_p, type='range', name=name_leaf1)
    infra_node_blk = cobra.model.infra.NodeBlk(infra_leaf_s, to_=node1, from_=node1, name='block0')

    if type(node_ids) == list:
        if len(node_ids) == 2:
            name_leaf2 = "sw" + str(node_ids[1])
            infra_leaf_s2 = cobra.model.infra.LeafS(infra_node_p, type='range', name=name_leaf2)
            infra_node_blk2 = cobra.model.infra.NodeBlk(infra_leaf_s2, to_=node_ids[1], from_=node_ids[1],
                                                        name='block1')
        elif len(node_ids) > 2:
            raise SystemError("Only 2 nodes allowed")

    apic_commit(md, top_mo, debug)


def register_switch(md, node_id, hostname, sw_serial, debug=False):
    """This function will register the switch with the fabric using the supplied info

    :param md: The Model Directory created from the login information
    :param node_id: Just that the node_id used to register the switch.  Should be four digits
    :param hostname: duh
    :param sw_serial: Chassis Serial number
    :param debug: if debuging is on or off
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/controller/nodeidentpol/nodep-%s' % sw_serial)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    fabric_node_ident_p = cobra.model.fabric.NodeIdentP(top_mo, name=hostname, nodeId=node_id, serial=sw_serial)

    apic_commit(md, top_mo, debug)


def create_node_mgmt_addr(md, node_id, inband_gw, inband_ip, outband_gw, outband_ip, debug=False):
    """This function will create the in/outband address pools, create a node block and assign the address pools
    and switch node based on what is in DNS

    :param md: The Model Directory created from the login information
    :param node_id: Just that the node_id used to register the switch.  Should be four digits
    :param inband_gw: This is the gateway addres of the subnet associated to the inb BD for management
    :param inband_ip: Management address that travels through the fabric
    :param outband_gw: This is the SM-ETH VLAN Gateway's HSRP address
    :param outband_ip: SM-ETH address for -econ
    :param debug: if debuging is on or off
    :return:
    """
    # the top level object on which operations will be made
    top_mo = cobra.model.pol.Uni('')

    fv_tenant = cobra.model.fv.Tenant(top_mo, name='mgmt')
    fvns_addr_inst = cobra.model.fvns.AddrInst(fv_tenant, addr=inband_gw, name='sw%s-mgmtinbaddr' % node_id)
    fvns_ucast_addr_blk = cobra.model.fvns.UcastAddrBlk(fvns_addr_inst, from_=inband_ip, to=inband_ip)
    fvns_addr_inst2 = cobra.model.fvns.AddrInst(fv_tenant, addr=outband_gw, name='sw%s-mgmtoobaddr' % node_id)
    fvns_ucast_addr_blk2 = cobra.model.fvns.UcastAddrBlk(fvns_addr_inst2, from_=outband_ip, to=outband_ip)

    apic_commit(md, fv_tenant, debug)

    # build the request using cobra syntax
    top_mo = cobra.model.pol.Uni('')

    infra_infra = cobra.model.infra.Infra(top_mo)
    infra_func_p = cobra.model.infra.FuncP(infra_infra)
    mgmt_grp = cobra.model.mgmt.Grp(infra_func_p, name='sw%s-mgmt' % node_id)
    mgmt_inb_zone = cobra.model.mgmt.InBZone(mgmt_grp, name='sw%s-mgmt' % node_id)
    mgmt_rs_addr_inst = cobra.model.mgmt.RsAddrInst(mgmt_inb_zone,
                                                    tDn='uni/tn-mgmt/addrinst-sw%s-mgmtinbaddr' % node_id)
    mgmt_rs_inb_epg = cobra.model.mgmt.RsInbEpg(mgmt_inb_zone, tDn='uni/tn-mgmt/mgmtp-default/inb-default')
    mgmt_oob_zone = cobra.model.mgmt.OoBZone(mgmt_grp)
    mgmt_rs_addr_inst2 = cobra.model.mgmt.RsAddrInst(mgmt_oob_zone,
                                                     tDn='uni/tn-mgmt/addrinst-sw%s-mgmtoobaddr' % node_id)
    mgmt_rs_oob_epg = cobra.model.mgmt.RsOobEpg(mgmt_oob_zone, tDn='uni/tn-mgmt/mgmtp-default/oob-default')
    mgmt_node_grp = cobra.model.mgmt.NodeGrp(infra_infra, type='range', name='sw%s-mgmt' % node_id)
    mgmt_rs_grp = cobra.model.mgmt.RsGrp(mgmt_node_grp, tDn='uni/infra/funcprof/grp-sw%s-mgmt' % node_id)
    infra_node_blk = cobra.model.infra.NodeBlk(mgmt_node_grp, from_=node_id, to_=node_id, name=node_id)

    apic_commit(md, infra_infra, debug)


""" Interface Functions """


def create_vpc_policy_grp(md, vpc_grp, vpc_id, node_ids, vpc_pol, debug=False):
    """

    :param md:
    :param vpc_grp: vPC protect group name
    :param vpc_id: This is the Domain ID for vPC
    :param node_ids: list of node_ids
    :param debug:
    :return:
    """
    if len(node_ids) == 2:
        node1 = node_ids[0]
        node2 = node_ids[1]
    else:
        raise SystemError("Must be 2 nodes in vPC Pair")

    top_dn = cobra.mit.naming.Dn.fromString('uni/fabric/protpol/expgep-%s' % vpc_grp)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    fabric_explicit_gep = cobra.model.fabric.ExplicitGEp(top_mo, name=vpc_grp, id=vpc_id)
    fabric_rs_vpc_inst_pol = cobra.model.fabric.RsVpcInstPol(fabric_explicit_gep, tnVpcInstPolName=vpc_pol)
    fabric_node_pep = cobra.model.fabric.NodePEp(fabric_explicit_gep, id=node1)
    fabric_node_pep2 = cobra.model.fabric.NodePEp(fabric_explicit_gep, id=node2)

    apic_commit(md, top_mo, debug)


def create_vpc_ifpolgrp(md, pol_name, aep_prfl, ll_pol, cdp_pol, lldp_pol, stp_pol, lacp_pol, debug=False):
    """

    :param md:
    :param pol_name:
    :param aep_prfl:
    :param ll_pol:
    :param cdp_pol:
    :param lldp_pol:
    :param stp_pol:
    :param lacp_pol:
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/funcprof/accbundle-%s' % pol_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    infra_acc_bndl_grp = cobra.model.infra.AccBndlGrp(top_mo, lagT='node', name=pol_name)
    infra_rs_att_ent_p = cobra.model.infra.RsAttEntP(infra_acc_bndl_grp, tDn='uni/infra/attentp-%s' % aep_prfl)
    infra_rs_hif_pol = cobra.model.infra.RsHIfPol(infra_acc_bndl_grp, tnFabricHIfPolName=ll_pol)
    infra_rs_cdp_if_pol = cobra.model.infra.RsCdpIfPol(infra_acc_bndl_grp, tnCdpIfPolName=cdp_pol)
    infra_rs_lldp_if_pol = cobra.model.infra.RsLldpIfPol(infra_acc_bndl_grp, tnLldpIfPolName=lldp_pol)
    infra_rs_stp_if_pol = cobra.model.infra.RsStpIfPol(infra_acc_bndl_grp, tnStpIfPolName=stp_pol)
    infra_rs_lacp_pol = cobra.model.infra.RsLacpPol(infra_acc_bndl_grp, tnLacpLagPolName=lacp_pol)

    apic_commit(md, top_mo, debug)


def create_ifprfl(md, prfl_name, switch_prfl, debug=False):
    """

    :param md:
    :param prfl_name: Interface Policy profile name for switch or leafpair
    :param switch_prfl: Switch Profile to add interface profile to
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/accportprof-%s' % prfl_name)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    infra_acc_port_p = cobra.model.infra.AccPortP(top_mo, name=prfl_name)

    apic_commit(md, top_mo, debug)

    top_mo = md.lookupByDn('uni/infra/nprof-%s' % switch_prfl)

    infra_rs_acc_port_p = cobra.model.infra.RsAccPortP(top_mo, tDn='uni/infra/accportprof-%s' % prfl_name)

    apic_commit(md, top_mo, debug)


def assign_subnet_bd(md, gw_address, subnet_scope, l3_route_prfl, debug=False):
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-mgmt/BD-inb/subnet-[%s]' % gw_address)
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # build the request using cobra syntax
    fv_subnet = cobra.model.fv.Subnet(top_mo, ip=gw_address, scope=subnet_scope)
    fv_rs_bd_subnet_to_profile = cobra.model.fv.RsBDSubnetToProfile(fv_subnet, tnL3extOutName=l3_route_prfl)

    apic_commit(md, top_mo, debug)


""" Network Security Policy Functions """


def create_tenant(md, tenant_name, debug=False):
    """ Used to create a tenant
    :param md: The Model Directory created from the login information
    :param tenant_name: Name of tenant to create
    :param debug: if debugging is on or off
    :return:
    """
    top_mo = cobra.model.pol.Uni('')

    fv_tenant = cobra.model.fv.Tenant(top_mo, name=tenant_name)

    apic_commit(md, top_mo, debug)


def create_filter(md, tenant_name, filter_name, debug=False):
    """ Used to create a filer
    :param md: The Model Directory created from the login information
    :param tenant_name: Name of tenant to create filter under
    :param filter_name: Name of filter object
    :param debug: if debuging is on or off
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/flt-%s' % (tenant_name, filter_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    vz_filter = cobra.model.vz.Filter(top_mo, name=filter_name)

    apic_commit(md, top_mo, debug)


def create_filter_entry(md, tenant_name, filter_name, entry_name, entry_details, debug=False):
    top_dn = cobra.mit.naming.Dn.fromString(u'uni/tn-%s/flt-%s/e-%s' % (tenant_name, filter_name, entry_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    # Process the attributes for filter entry
    if 'etherT' in entry_details.keys():
        ether_type = entry_details['etherT']
    else:
        ether_type = 'unspecified'
    if 'prot' in entry_details.keys():
        protocol = entry_details['prot']
    else:
        protocol = 'unspecified'
    if 'sFromPort' in entry_details.keys():
        src_from_port = entry_details['sFromPort']
    else:
        src_from_port = 'unspecified'
    if 'sToPort' in entry_details.keys():
        src_to_port = entry_details['sToPort']
    else:
        src_to_port = 'unspecified'
    if 'dFromPort' in entry_details.keys():
        dst_from_port = entry_details['dFromPort']
    else:
        dst_from_port = 'unspecified'
    if 'dToPort' in entry_details.keys():
        dst_to_port = entry_details['dToPort']
    else:
        dst_to_port = 'unspecified'
    if 'tcpRules' in entry_details.keys():
        tcp_rules = entry_details['tcpRules']
    else:
        tcp_rules = 'unspecified'

    vz_entry = cobra.model.vz.Entry(top_mo, name=entry_name,
                                    etherT=ether_type,
                                    prot=protocol,
                                    sFromPort=src_from_port,
                                    sToPort=src_to_port,
                                    dFromPort=dst_from_port,
                                    dToPort=dst_to_port,
                                    tcpRules=tcp_rules)

    apic_commit(md, top_mo, debug)


def create_contract(md, tenant_name, contract_name, contract_scope, debug=False):
    """ Used to create a contract
    :param md: The Model Directory created from the login information
    :param tenant_name: Name of tenant to create contract under
    :param contract_name: Name of the contract to be created
    :param contract_scope: Scope of contract
    :param debug: if debuging is on or off
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/brc-%s' % (tenant_name, contract_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    vz_br_cp = cobra.model.vz.BrCP(top_mo, name=contract_name, scope=contract_scope)

    apic_commit(md, top_mo, debug)


def create_contract_subject_uni(md,
                                tenant_name,
                                contract_name,
                                subject_name,
                                interm_filter_list,
                                outterm_filter_list,
                                debug=False):
    """ Used to create a uni-directional subject within a contract

    :param md: The Model Directory created from the login information
    :param tenant_name: Name of the tenant
    :param contract_name: Name of the contract
    :param subject_name: Name of the contract subject
    :param interm_filter_list: List of filters for 'input terminal'
    :param outterm_filter_list: List of filters for 'output terminal'
    :param debug: if debuging is on or off
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/brc-%s/subj-%s' % (tenant_name, contract_name, subject_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    vz_subj = cobra.model.vz.Subj(top_mo, name=subject_name)

    vz_outterm = cobra.model.vz.OutTerm(vz_subj)
    for outterm_filter in outterm_filter_list:
        vz_rsfiltatt = cobra.model.vz.RsFiltAtt(vz_outterm, tnVzFilterName=outterm_filter)

    vz_interm = cobra.model.vz.InTerm(vz_subj)
    for interm_filter in interm_filter_list:
        vz_rsfiltatt = cobra.model.vz.RsFiltAtt(vz_interm, tnVzFilterName=interm_filter)

    apic_commit(md, top_mo, debug)


def create_contract_subject_bi(md, tenant_name, contract_name, subject_name, filter_list, debug=False):
    """
    Used to create a bi-directional subject within a contract
    :param md: he Model Directory created from the login information
    :param tenant_name: Name of the tenant
    :param contract_name: Name of the contract
    :param subject_name: Name of the contract subject
    :param filter_list: List of filters
    :param debug: if debuging is on or off
    :return:
    """

    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/brc-%s/subj-%s' % (tenant_name, contract_name, subject_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    vz_subj = cobra.model.vz.Subj(top_mo, name=subject_name)

    for f in filter_list:
        vz_rssub_filter_att = cobra.model.vz.RsSubjFiltAtt(vz_subj, tnVzFilterName=f)

    apic_commit(md, top_mo, debug)


def create_l3out(md, tenant_name, l3out_name, debug=False):
    """

    :param md: The Model Directory created from the login information
    :param tenant_name: Name of the tenant
    :param l3out_name: Name of routed external network (L3Out)
    :param debug: if debugging is on or off
    :return:
    """

    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/out-%s' % (tenant_name, l3out_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    l3ext_out = cobra.model.l3ext.Out(top_mo, name=l3out_name)

    apic_commit(md, top_mo, debug)


def create_external_network(md, tenant_name, l3out_name, extnet_name, network_list, debug=False):
    """
    Used to create an external network in a L3Out
    :param md: The Model Directory created from the login information
    :param tenant_name: Name of the tenant
    :param l3out_name: Name of routed external network (L3Out)
    :param extnet_name: Name of the external network group
    :param network_list: List of IP networks
    :param debug: if debugging is on or off
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/out-%s/instP-%s' % (tenant_name, l3out_name, extnet_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    l3_ext_instp = cobra.model.l3ext.InstP(top_mo, name=extnet_name)
    for network in network_list:
        l3_ext_subnet = cobra.model.l3ext.Subnet(l3_ext_instp, ip=network)

    apic_commit(md, top_mo, debug)


def config_extnet_contract(md, tenant_name, l3out_name, extnet_name, provide_list, consume_list, debug=False):
    """

    :param md: The Model Directory created from the login information
    :param tenant_name: Name of the tenant
    :param l3out_name: Name of routed external network (L3Out)
    :param extnet_name: Name of the external network group
    :param provide_list: List of provided contracts
    :param consume_list: List of consumed contracts
    :param debug: if debugging is on or off
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/out-%s/instP-%s' % (tenant_name, l3out_name, extnet_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    l3_ext_instp = cobra.model.l3ext.InstP(top_mo, name=extnet_name)

    for provide in provide_list:
        fv_rs_prov = cobra.model.fv.RsProv(l3_ext_instp, tnVzBrCPName=provide)
    for consume in consume_list:
        fv_rs_cons = cobra.model.fv.RsCons(l3_ext_instp, tnVzBrCPName=consume)

    apic_commit(md, top_mo, debug)


def create_vrf(md, tenant_name, vrf_name, debug=False):
    """
    Used to create a VRF
    :param md: The Model Directory created from the login information
    :param tenant_name: Name of the tenant
    :param vrf_name: Name of private network context (VRF)
    :param debug: if debugging is on or off
    :return:
    """
    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/ctx-%s' % (tenant_name, vrf_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    fv_ctx = cobra.model.fv.Ctx(top_mo, name=vrf_name)

    apic_commit(md, top_mo, debug)


def config_vrf_contract(md, tenant_name, vrf_name, provide_list, consume_list, debug=False):

    top_dn = cobra.mit.naming.Dn.fromString('uni/tn-%s/ctx-%s' % (tenant_name, vrf_name))
    top_parent_dn = top_dn.getParent()
    top_mo = md.lookupByDn(top_parent_dn)

    fv_ctx = cobra.model.fv.Ctx(top_mo, name=vrf_name)
    vz_any = cobra.model.vz.Any(fv_ctx)

    for provide in provide_list:
        vz_rs_any_to_prov = cobra.model.vz.RsAnyToProv(vz_any, tnVzBrCPName=provide)
    for consume in consume_list:
        vz_rs_any_to_cons = cobra.model.vz.RsAnyToCons(vz_any, tnVzBrCPName=consume)

    apic_commit(md, top_mo, debug)


def add_tacacs_server(md, tacacs_server, description, key, order, debug=False):
    pol_uni = cobra.model.pol.Uni('')
    aaa_user_ep = cobra.model.aaa.UserEp(pol_uni)
    aaa_tacacs_plus_ep = cobra.model.aaa.TacacsPlusEp(aaa_user_ep,
                                                      retries='1',
                                                      ownerKey='',
                                                      name='',
                                                      descr='',
                                                      timeout='5',
                                                      ownerTag='')

    aaa_tacacs_plus_provider = cobra.model.aaa.TacacsPlusProvider(aaa_tacacs_plus_ep,
                                                                  retries='1',
                                                                  ownerKey=key,
                                                                  name=tacacs_server,
                                                                  descr=description,
                                                                  timeout='5',
                                                                  authProtocol='pap',
                                                                  monitoringUser='test',
                                                                  monitorServer='disabled',
                                                                  ownerTag='', port='49')

    aaa_rs_sec_prov_to_epg = cobra.model.aaa.RsSecProvToEpg(aaa_tacacs_plus_provider,
                                                            tDn='uni/tn-mgmt/mgmtp-default/oob-default')

    aaa_tacacs_plus_provider_group = cobra.model.aaa.TacacsPlusProviderGroup(aaa_tacacs_plus_ep,
                                                                             ownerKey='',
                                                                             name='TACACS-ProvGrp',
                                                                             descr='', ownerTag='')

    aaa_provider_ref = cobra.model.aaa.ProviderRef(aaa_tacacs_plus_provider_group,
                                                   ownerKey='',
                                                   ownerTag='',
                                                   name=tacacs_server,
                                                   descr=description,
                                                   order=order)

    # commit the generated code to APIC
    apic_commit(md, aaa_user_ep, debug)


def login_domains(md, debug=False):
    # Setup Local and TACACS Domains
    pol_uni = cobra.model.pol.Uni('')
    aaa_user_ep = cobra.model.aaa.UserEp(pol_uni)

    # Add localAdmin Domain
    aaa_login_domain_local = cobra.model.aaa.LoginDomain(aaa_user_ep,
                                                         ownerKey='',
                                                         name='localAdmin',
                                                         descr='Local admin account', ownerTag='')
    aaa_domain_local_auth = cobra.model.aaa.DomainAuth(aaa_login_domain_local,
                                                       ownerKey='',
                                                       realm='local',
                                                       name='', descr='',
                                                       providerGroup='',
                                                       ownerTag='')

    # Add TACACS Domain
    aaa_login_domain_tacacs = cobra.model.aaa.LoginDomain(aaa_user_ep,
                                                          ownerKey='',
                                                          name='TACACS',
                                                          descr='TACACS ARBAC Test',
                                                          ownerTag='')
    aaa_domain_tacacs_auth = cobra.model.aaa.DomainAuth(aaa_login_domain_tacacs,
                                                        ownerKey='',
                                                        realm='tacacs',
                                                        name='', descr='',
                                                        providerGroup='TACACS-ProvGrp',
                                                        ownerTag='')

    # commit the generated code to APIC
    apic_commit(md, aaa_user_ep, debug)


# def add_snmp(md, location, contact, snmp_user, debug=False):
#     # Setup Local and TACACS Domains
#     topDn = cobra.mit.naming.Dn.fromString('uni/fabric/snmppol-default')
#     topParentDn = topDn.getParent()
#     topMo = md.lookupByDn(topParentDn)
#
#     # build the request using cobra syntax
#     snmpPol = cobra.model.snmp.Pol(topMo, loc='RTP1', ownerKey='', name='default', descr='', adminSt='enabled',
#                                    contact='network-ops-dc', ownerTag='')
#     snmpUserP = cobra.model.snmp.UserP(snmpPol, authType='hmac-sha1-96', privType='aes-128', name='network-v3user',
#                                        descr='')


def create_backup_policy(md, remote_host, remote_path, username, password, protocol='sftp', port='22', debug=False):
    # Setup Remote Location
    topDn = cobra.mit.naming.Dn.fromString('uni/fabric/path-%s' % remote_host)
    topParentDn = topDn.getParent()
    topMo = md.lookupByDn(topParentDn)

    # build the request using cobra syntax
    fileRemotePath = cobra.model.file.RemotePath(topMo, remotePort=port, protocol=protocol, name=remote_host,
                                                 descr='', userName=username, userPasswd=password, host=remote_host,
                                                 remotePath=remote_path)
    fileRsARemoteHostToEpg = cobra.model.file.RsARemoteHostToEpg(fileRemotePath,
                                                                 tDn='uni/tn-mgmt/mgmtp-default/oob-default')


    # Setup Daily export to remote location
    topDn = cobra.mit.naming.Dn.fromString('uni/fabric/configexp-Daily')
    topParentDn = topDn.getParent()
    topMo = md.lookupByDn(topParentDn)
    configExportP = cobra.model.config.ExportP(topMo, targetDn='', name='Daily', descr='', format='xml',
                                               adminSt='untriggered', maxSnapshotCount='global-limit', snapshot='no',
                                               includeSecureFields='yes')
    configRsRemotePath = cobra.model.config.RsRemotePath(configExportP, tnFileRemotePathName=remote_host)
    configRsExportScheduler = cobra.model.config.RsExportScheduler(configExportP, tnTrigSchedPName='Daily-Midnight')

    # commit the generated code to APIC
    apic_commit(md, fileRemotePath, debug)
    apic_commit(md, configExportP, debug)