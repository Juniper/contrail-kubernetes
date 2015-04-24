#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import argparse
import iniparse
import json
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

    def InterfaceLookup(self, uid):
        try:
            vmi = self._client.virtual_machine_interface_read(id=uid)
            return vmi
        except NoIdError:
            return None

# end class ContrailClient


def plugin_init():
    client = ContrailClient()
    client.LocateRouter(socket.gethostname(), client.local_address())
# end plugin_init


def docker_get_pid(docker_id):
    pid_str = Shell.run('docker inspect -f \'{{.State.Pid}}\' %s' % docker_id)
    return int(pid_str)


def kubelet_get_api():
    fp = open('/etc/kubernetes/kubelet', 'r')
    for line in fp.readlines():
        m = re.search(r'KUBELET_API_SERVER=\"--api_servers=http://(.*)\"', line)
        if m:
            return m.group(1)
    return None

def getPodInfo(docker_id):
    name = Shell.run('docker inspect -f \'{{.Name}}\' %s' % docker_id)
    
    # Name
    # See: pkg/kubelet/dockertools/docker.go:ParseDockerName
    # name_namespace_uid
    fields = name.rstrip().split('_')

    podName = fields[2]
    uid = fields[4]

    kubeapi = kubelet_get_api()

    data = Shell.run('kubectl --server=%s get -o json pod %s' % (
        kubeapi, podName))
    return uid, json.loads(data)
    
def setup(pod_namespace, pod_name, docker_id):
    """
    project: pod_namespace
    network: pod_name
    netns: docker_id{12}
    """
    client = ContrailClient()

    # Kubelet::createPodInfraContainer ensures that State.Pid is set
    pid = docker_get_pid(docker_id)
    if pid == 0:
        raise Exception('Unable to read State.Pid')

    short_id = docker_id[0:11]

    if not os.path.exists('/var/run/netns'):
        os.mkdir('/var/run/netns')

    Shell.run('ln -sf /proc/%d/ns/net /var/run/netns/%s' % (pid, short_id))

    manager = LxcManager()

    if client._net_mode == 'none':
        instance_ifname = 'veth0'
    else:
        instance_ifname = 'eth0'

    uid, podInfo = getPodInfo(docker_id)
    # TODO: Remove the need for a vmi lookup.
    # The lxc_manager uses the mac_address to setup the container interface.
    # Additionally the ip-address, prefixlen and gateway are also used.
    if not 'annotations' in podInfo:
        logging.error('No annotations in pod %s', podInfo["metadata"]["name"])
        sys.exit(1)

    vmi = client.InterfaceLookup(podInfo["annotations"]["vmi"])
    if vmi == None:
        logging.error("Interface not found %s" % (
            podInfo["annotations"]["vmi"]))
        sys.exit(1)

    if client._net_mode == 'none':
        ifname = manager.create_interface(short_id, instance_ifname, vmi)
    else:
        ifname = manager.move_interface(short_id, pid, instance_ifname, vmi)

    interface_register(uid, vmi, ifname)
    provisioner = Provisioner(api_server=client._server)
    (ipaddr, plen, gw) = provisioner.get_interface_ip_info(vmi)
    Shell.run('ip netns exec %s ip addr add %s/32 peer %s dev %s' % \
              (short_id, ipaddr, gw, instance_ifname))
    Shell.run('ip netns exec %s ip route add default via %s' % \
              (short_id, gw))
    Shell.run('ip netns exec %s ip link set %s up' %
              (short_id, instance_ifname))


def teardown(pod_namespace, pod_name, docker_id):
    client = ContrailClient()
    manager = LxcManager()
    short_id = docker_id[0:11]

    uid, podInfo = getPodInfo(docker_id)
    if 'annotations' in podInfo and 'vmi' in podInfo["annotations"]:
        vmi = podInfo["annotations"]["vmi"]
        interface_unregister(vmi)

    manager.clear_interfaces(short_id)
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
