#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import argparse
import iniparse
import logging
import os
import re
import socket
import subprocess
import sys
import uuid

import vnc_api.vnc_api as opencontrail

from instance_provisioner import Provisioner
from lxc_manager import LxcManager
from vrouter_control import interface_register, interface_unregister
from shell import Shell

class ContrailClient(object):
    def __init__(self):
        self._server = None
        self._net_mode = "bridge"
        self._readconfig()
        self._client = opencontrail.VncApi(api_server_host=self._server)

    def _readconfig(self):
        """ Expects a configuration file in the same directory as the
        executable.
        """
        path = os.path.normpath(sys.argv[0])
        filename = os.path.join(os.path.dirname(path), 'config')
        config = iniparse.INIConfig(open(filename))
        self._server = config['DEFAULTS']['api_server']
        self._net_mode = config['DEFAULTS']['net_mode']

    def local_address(self):
        output = Shell.run('ip addr show vhost0')
        expr = re.compile(r'inet ((([0-9]{1,3})\.){3}([0-9]{1,3}))/(\d+)')
        m = expr.search(output)
        if not m:
            raise Exception('Unable to determine local IP address')
        return m.group(1)

    def LocateRouter(self, hostname, localip):
        try:
            fqn = ['default-global-system-config', hostname]
            vrouter = self._client.virtual_router_read(fq_name=fqn)
            return vrouter
        except opencontrail.NoIdError:
            pass

        logging.debug('Creating virtual-router for %s:%s' %
                      (hostname, localip))
        vrouter = opencontrail.VirtualRouter(
            hostname,
            virtual_router_ip_address=localip)
        self._client.virtual_router_create(vrouter)

    def _create_default_security_group(self, project):
        def _create_rule(egress, sg, prefix, ethertype):
            local = opencontrail.AddressType(security_group='local')
            if sg:
                group = project.get_fq_name() + [sg]
                addr = opencontrail.AddressType(
                    security_group=':'.join(group))
            elif prefix:
                addr = opencontrail.AddressType(
                    subnet=opencontrail.SubnetType(prefix, 0))

            src = local if egress else addr
            dst = addr if egress else local
            return opencontrail.PolicyRuleType(
                rule_uuid=uuid.uuid4(), direction='>', protocol='any',
                src_addresses=[src],
                src_ports=[opencontrail.PortType(0, 65535)],
                dst_addresses=[dst],
                dst_ports=[opencontrail.PortType(0, 65535)],
                ethertype=ethertype)

        rules = [
            _create_rule(False, 'default', None, 'IPv4'),
            _create_rule(True, None, '0.0.0.0', 'IPv4')
        ]

        sg_group = opencontrail.SecurityGroup(
            name='default', parent_obj=project,
            security_group_entries=opencontrail.PolicyEntriesType(rules))

        self._client.security_group_create(sg_group)
        return sg_group

    def _locate_default_security_group(self, project):
        sg_groups = project.get_security_groups()
        for sg_group in sg_groups or []:
            if sg_group['to'][-1] == 'default':
                return sg_group
        return self._create_default_security_group(project)

    def LocateProject(self, project_name):
        fqn = ['default-domain', project_name]
        try:
            project = self._client.project_read(fq_name=fqn)
        except opencontrail.NoIdError:
            logging.debug('Creating project %s' % project_name)
            project = opencontrail.Project(project_name)
            self._client.project_create(project)

        # self._locate_default_security_group(project)
        return project

    def LocateNetwork(self, project, network_name):
        def _add_subnet(network, subnet):
            fqn = project.get_fq_name() + ['default-network-ipam']
            try:
                ipam = self._client.network_ipam_read(fq_name=fqn)
            except opencontrail.NoIdError:
                ipam = opencontrail.NetworkIpam('default-network-ipam',
                                                parent_obj=project)
                self._client.network_ipam_create(ipam)
            (prefix, plen) = subnet.split('/')
            subnet = opencontrail.IpamSubnetType(
                subnet=opencontrail.SubnetType(prefix, int(plen)))
            network.add_network_ipam(ipam,
                                     opencontrail.VnSubnetsType([subnet]))

        fqn = project.get_fq_name() + [network_name]
        try:
            network = self._client.virtual_network_read(fq_name=fqn)
        except opencontrail.NoIdError:
            logging.debug('Creating network %s' % network_name)
            network = opencontrail.VirtualNetwork(
                network_name, parent_obj=project)
            _add_subnet(network, '10.0.0.0/8')
            self._client.virtual_network_create(network)

        return network

# end class ContrailClient


def plugin_init():
    client = ContrailClient()
    client.LocateRouter(socket.gethostname(), client.local_address())
# end plugin_init


def docker_get_pid(docker_id):
    pid_str = Shell.run('docker inspect -f \'{{.State.Pid}}\' %s' % docker_id)
    return int(pid_str)


def setup(pod_namespace, pod_name, docker_id):
    """
    project: pod_namespace
    network: pod_name
    netns: docker_id{12}
    """
    client = ContrailClient()
    project = client.LocateProject(pod_namespace)
    # client.LocateNetwork(pod_name)
    network = client.LocateNetwork(project, 'default')

    # Kubelet::createPodInfraContainer ensures that State.Pid is set
    pid = docker_get_pid(docker_id)
    if pid == 0:
        raise Exception('Unable to read State.Pid')

    short_id = docker_id[0:11]

    if not os.path.exists('/var/run/netns'):
        os.mkdir('/var/run/netns')

    Shell.run('ln -sf /proc/%d/ns/net /var/run/netns/%s' % (pid, short_id))

    # Name
    # See: pkg/kubelet/docker/tools/docker.go:ParseDockerName
    # name_namespace_uid

    # list curl -k https://127.0.0.1:10250/pods
    # find pod by uid.
    
    manager = LxcManager()
    provisioner = Provisioner(api_server=client._server)
    vm = provisioner.virtual_machine_locate(short_id)

    if client._net_mode == 'none':
        instance_ifname = 'veth0'
    else:
        instance_ifname = 'eth0'

    vmi = provisioner.vmi_locate(vm, project, network, instance_ifname)
    if client._net_mode == 'none':
        ifname = manager.create_interface(short_id, instance_ifname, vmi)
    else:
        ifname = manager.move_interface(short_id, pid, instance_ifname, vmi)

    interface_register(vm, vmi, ifname)
    (ipaddr, plen) = provisioner.get_interface_ip_prefix(vmi)
    Shell.run('ip netns exec %s ip addr add %s/%d dev %s' % \
              (short_id, ipaddr, plen, instance_ifname))
    Shell.run('ip netns exec %s ip link set %s up' %
              (short_id, instance_ifname))


def teardown(pod_namespace, pod_name, docker_id):
    client = ContrailClient()
    provisioner = Provisioner(api_server=client._server)
    manager = LxcManager()
    short_id = docker_id[0:11]

    vm = provisioner.virtual_machine_lookup(short_id)
    if vm is not None:
        vmi_list = vm.get_virtual_machine_interface_back_refs()
        for ref in vmi_list or []:
            uuid = ref['uuid']
            interface_unregister(uuid)

        manager.clear_interfaces(short_id)

        for ref in vmi_list:
            provisioner.vmi_delete(ref['uuid'])

        provisioner.virtual_machine_delete(vm)

    Shell.run('ip netns delete %s' % short_id)


def main():
    logging.basicConfig(filename='/var/log/contrail/kubelet-driver.log',
                        level=logging.DEBUG)
    logging.debug(' '.join(sys.argv))
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="action", dest='action')

    init_parser = subparsers.add_parser('init')

    cmd_parser = argparse.ArgumentParser(add_help=False)
    cmd_parser.add_argument('pod_namespace')
    cmd_parser.add_argument('pod_name')
    cmd_parser.add_argument('docker_id')

    setup_parser = subparsers.add_parser('setup', parents=[cmd_parser])
    teardown_parser = subparsers.add_parser('teardown', parents=[cmd_parser])

    args = parser.parse_args()

    if args.action == 'init':
        plugin_init()
    elif args.action == 'setup':
        setup(args.pod_namespace, args.pod_name, args.docker_id)
    elif args.action == 'teardown':
        teardown(args.pod_namespace, args.pod_name, args.docker_id)

if __name__ == '__main__':
    main()
