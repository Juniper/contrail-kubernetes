#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import argparse
import iniparse
import json
import logging
import os
import re
import requests
import socket
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ElementTree

import vnc_api.vnc_api as opencontrail

from contrail_vrouter_api.vrouter_api import ContrailVRouterApi
from lxc_manager import LxcManager
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

# end class ContrailClient


def plugin_init():
    client = ContrailClient()
    client.LocateRouter(socket.gethostname(), client.local_address())
# end plugin_init


def docker_get_pid(docker_id):
    pid_str = Shell.run('docker inspect -f \'{{.State.Pid}}\' %s' % docker_id)
    return int(pid_str)

# kubelet config is at different places in different envs, unfortunately
def kubelet_get_api():
    fp = None
    try:
        fp = open('/etc/sysconfig/kubelet', 'r')
    except:
        try:
            fp = open('/etc/default/kubelet', 'r')
        except:
            fp = open('/etc/kubernetes/kubelet', 'r')

    for line in fp.readlines():
        m = re.search(r'--api_servers=http[s]?://(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            return m.group(1)
    return None

def getDockerPod(docker_id):
    name = Shell.run('docker inspect -f \'{{.Name}}\' %s' % docker_id)
    
    # Name
    # See: pkg/kubelet/dockertools/docker.go:ParseDockerName
    # name_namespace_uid
    fields = name.rstrip().split('_')

    podName = fields[2]
    uid = fields[4]
    return uid, podName

def getPodInfo(podName):
    kubeapi = kubelet_get_api()

    data = Shell.run('/usr/local/bin/kubectl --server=%s:7080 get -o json pod %s' % (
            kubeapi, podName), True)
    return json.loads(data)
    
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

    uid, podName = getDockerPod(docker_id)

    podInfo = None
    for i in range(0, 120):
        podInfo = getPodInfo(podName)
        if 'annotations' in podInfo["metadata"] and \
           'nic_uuid' in podInfo["metadata"]["annotations"]:
            break
        time.sleep(1)
    
    # The lxc_manager uses the mac_address to setup the container interface.
    # Additionally the ip-address, prefixlen and gateway are also used.
    if not 'annotations' in podInfo["metadata"] or not 'nic_uuid' in podInfo["metadata"]["annotations"]:
        logging.error('No annotations in pod %s', podInfo["metadata"]["name"])
        sys.exit(1)


    podAnnotations = podInfo["metadata"]["annotations"]
    nic_uuid = podAnnotations["nic_uuid"]
    mac_address = podAnnotations["mac_address"]
    if client._net_mode == 'none':
        ifname = manager.create_interface(short_id, instance_ifname,
                                          mac_address)
    else:
        ifname = manager.move_interface(short_id, pid, instance_ifname,
                                        mac_address)

    api = ContrailVRouterApi()
    api.add_port(uid, nic_uuid, ifname, mac_address,
                 port_type='NovaVMPort',
                 display_name=podName,
                 hostname=podName+'.'+pod_namespace)

    ip_address = podAnnotations["ip_address"]
    gateway = podAnnotations["gateway"]
    Shell.run('ip netns exec %s ip addr add %s/32 peer %s dev %s' % \
              (short_id, ip_address, gateway, instance_ifname))
    Shell.run('ip netns exec %s ip route add default via %s' % \
              (short_id, gateway))
    Shell.run('ip netns exec %s ip link set %s up' %
              (short_id, instance_ifname))

def vrouter_interface_by_name(vmName):
    r = requests.get('http://localhost:8085/Snh_ItfReq')
    root = ElementTree.fromstring(r.text)
    for interface in root.iter('ItfSandeshData'):
        vm = interface.find('vm_name')
        if vm is not None and vm.text == vmName:
            vmi = interface.find('uuid')
            return vmi.text
    return None

def teardown(pod_namespace, pod_name, docker_id):
    client = ContrailClient()
    manager = LxcManager()
    short_id = docker_id[0:11]

    api = ContrailVRouterApi()

    _, podName = getDockerPod(docker_id)
    vmi = vrouter_interface_by_name(podName)
    if vmi is not None:
        api.delete_port(vmi)

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
    try:
        main()
    except:
        logging.error("Unexpected error: %s", sys.exc_info()[0])
        raise
