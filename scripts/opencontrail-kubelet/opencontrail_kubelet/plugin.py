#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import argparse
import distutils.spawn
import json
import logging
import os
import requests
import sys
import time
import xml.etree.ElementTree as ElementTree

from vrouter_api import ContrailVRouterApi
from lxc_manager import LxcManager
from shell import Shell

opt_net_mode = "bridge"


def docker_get_pid(docker_id):
    pid_str = Shell.run('docker inspect -f \'{{.State.Pid}}\' %s' % docker_id)
    return int(pid_str)


def getDockerPod(docker_id):
    name = Shell.run('docker inspect -f \'{{.Name}}\' %s' % docker_id)

    # Name
    # See: pkg/kubelet/dockertools/docker.go:ParseDockerName
    # name_namespace_uid
    fields = name.rstrip().split('_')

    podName = fields[2]
    uid = fields[4]
    return uid, podName


def getPodInfo(namespace, podName):
    r = requests.get('http://localhost:10255/pods')
    if r.status_code != requests.codes.ok:
        logging.error("%s: %s", 'http://localhost:10255/pods', r.text)
        return None

    podItems = json.loads(r.text)

    for pod in podItems["items"]:
        if 'metadata' not in pod:
            continue
        meta = pod['metadata']
        if meta['namespace'] == namespace and meta['name'] == podName:
            logging.debug('pod %s %s', podName, pod['status'])
            return pod

    logging.error('%s not present in kubelet cache' % podName)
    return None


def init():
    """ Ensure that the following tools are available on the PATH """
    executables = ['ethtool', 'brctl']
    for prog in executables:
        if distutils.spawn.find_executable(prog) is None:
            logging.error('%s not in PATH' % prog)
            sys.exit(1)


def setup(pod_namespace, pod_name, docker_id):
    """
    project: pod_namespace
    network: pod_name
    netns: docker_id{12}
    """

    # Kubelet::createPodInfraContainer ensures that State.Pid is set
    pid = docker_get_pid(docker_id)
    if pid == 0:
        raise Exception('Unable to read State.Pid')

    short_id = docker_id[0:11]

    if not os.path.exists('/var/run/netns'):
        os.mkdir('/var/run/netns')

    Shell.run('ln -sf /proc/%d/ns/net /var/run/netns/%s' % (pid, short_id))

    manager = LxcManager()

    if opt_net_mode == 'none':
        instance_ifname = 'veth0'
    else:
        instance_ifname = 'eth0'

    uid, podName = getDockerPod(docker_id)
    podInfo = None
    podState = None
    for i in range(0, 30):
        podInfo = getPodInfo(pod_namespace, podName)
        if podInfo is None:
            sys.exit(1)
        if 'hostNetwork' in podInfo['spec'] and \
           podInfo['spec']['hostNetwork']:
            sys.exit(0)
        if 'annotations' in podInfo["metadata"] and \
           'opencontrail.org/pod-state' in podInfo["metadata"]["annotations"]:
            podState = json.loads(
                podInfo["metadata"]["annotations"]
                ["opencontrail.org/pod-state"])
            break
        time.sleep(1)

    # The lxc_manager uses the mac_address to setup the container interface.
    # Additionally the ip-address, prefixlen and gateway are also used.
    if podState is None:
        logging.error('No annotations in pod %s', podInfo["metadata"]["name"])
        sys.exit(1)

    nic_uuid = podState["uuid"]
    mac_address = podState["macAddress"]
    if opt_net_mode == 'none':
        ifname = manager.create_interface(short_id, instance_ifname,
                                          mac_address)
    else:
        ifname = manager.move_interface(short_id, pid, mac_address)

    api = ContrailVRouterApi()
    api.add_port(uid, nic_uuid, ifname, mac_address,
                 port_type='NovaVMPort',
                 display_name=podName,
                 hostname=podName+'.'+pod_namespace)

    ip_address = podState["ipAddress"]
    gateway = podState["gateway"]
    Shell.run('ip netns exec %s ip addr add %s/32 peer %s dev %s' %
              (short_id, ip_address, gateway, instance_ifname))
    Shell.run('ip netns exec %s ip route add default via %s' %
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
            return vmi.text, interface
    return None, None


def teardown(pod_namespace, pod_name, docker_id):
    manager = LxcManager()
    short_id = docker_id[0:11]

    api = ContrailVRouterApi()

    uid, podName = getDockerPod(docker_id)
    vmi, _ = vrouter_interface_by_name(podName)
    if vmi is not None:
        api.delete_port(vmi)

    manager.clear_interfaces(short_id)
    Shell.run('ip netns delete %s' % short_id)


class PodNetworkStatus(object):
    def __init__(self):
        self.kind = 'PodNetworkStatus'
        self.apiVersion = 'v1beta1'
        self.ip = None


def podHasLivenessProbe(podInfo):
    for container in podInfo['spec']['containers']:
        if 'livenessProbe' in container:
            return True
    return False


def status(pod_namespace, pod_name, docker_id):
    status = PodNetworkStatus()
    uid, podName = getDockerPod(docker_id)
    vmi, data = vrouter_interface_by_name(podName)
    if vmi is None:
        setup(pod_namespace, pod_name, docker_id)
        return

    podInfo = getPodInfo(pod_namespace, podName)
    if podInfo and podHasLivenessProbe(podInfo):
        localaddr = data.find('mdata_ip_addr')
    else:
        localaddr = data.find('ip_addr')

    if localaddr is not None:
        status.ip = localaddr.text
    print json.dumps(status.__dict__)


def main():
    logging.basicConfig(filename='/var/log/contrail/kubelet-driver.log',
                        level=logging.DEBUG)
    logging.debug(' '.join(sys.argv))
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="action", dest='action')

    subparsers.add_parser('init')

    cmd_parser = argparse.ArgumentParser(add_help=False)
    cmd_parser.add_argument('pod_namespace')
    cmd_parser.add_argument('pod_name')
    cmd_parser.add_argument('docker_id')

    subparsers.add_parser('setup', parents=[cmd_parser])
    subparsers.add_parser('teardown', parents=[cmd_parser])
    subparsers.add_parser('status', parents=[cmd_parser])

    args = parser.parse_args()

    try:
        if args.action == 'init':
            init()
        elif args.action == 'setup':
            setup(args.pod_namespace, args.pod_name, args.docker_id)
        elif args.action == 'teardown':
            teardown(args.pod_namespace, args.pod_name, args.docker_id)
        elif args.action == 'status':
            status(args.pod_namespace, args.pod_name, args.docker_id)
    except Exception as ex:
        logging.error(ex)
        if args.action == 'setup':
            sys.exit(0)
        sys.exit(1)

if __name__ == '__main__':
    main()
