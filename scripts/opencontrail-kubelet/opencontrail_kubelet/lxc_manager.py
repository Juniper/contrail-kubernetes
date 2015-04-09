import logging
import re
import subprocess
import sys


def shell_command(str):
    cmd = subprocess.check_output(str, shell=True)
    logging.debug('Ran shell command: %s' % str)
    logging.debug('output: %s' % cmd.rstrip())
    return cmd


class LxcManager(object):
    def __init__(self):
        pass

    def _interface_generate_unique_name(self):
        output = shell_command('ip link list')
        ids = {}

        for line in output.split('\n'):
            m = re.match(r'[\d]+: instance([\d]+)', line)
            if m:
                ids[m.group(1)] = True

        for i in range(256):
            if str(i) in ids:
                continue
            return 'instance%d' % i
        return None

    # Find the correct interface for this nsname
    def interface_find_peer_name(self, ifname_instance, pid):
        ns_ifindex = shell_command("echo ethtool -S %s | sudo nsenter -n -t %s sh | grep peer_ifindex | awk '{print $2}'" % (ifname_instance, pid))

        # Now look through all interfaces in the bridge and find the one whose
        # ifindex is 1 less than ns_ifindex
        bridge_members = [ i[i.find("veth"):] for i in \
                  shell_command("brctl show docker0 | grep veth").split("\n") \
        ]

        # Remove the trailing empty string, which comes as a result of split.
        bridge_members.pop()
        bridge_members_ifindex = [ shell_command( \
            "ethtool -S %s | grep peer_ifindex | awk '{print $2}'" % i) \
                for i in bridge_members ]
        try:
            member_index = bridge_members_ifindex.index('%s\n' % \
                (int(ns_ifindex) - 1))
        except:
            logging.info('did not find member %s' % bridge_members[member_index])
            logging.error "Cannot find matching veth interface among brige members")
            raise
        logging.info('found member %s' % bridge_members[member_index])
        return bridge_members[member_index]

    # Remove the interface out of the docker bridge
    def move_interface(self, nsname, pid, ifname_instance, vmi):
        ifname_master = self.interface_find_peer_name(ifname_instance, pid)
        # shell_command('brctl delif docker0 %s' % ifname_master)
        if vmi:
            mac = vmi.virtual_machine_interface_mac_addresses.mac_address[0]
            shell_command('ip netns exec %s hw ether %s' % (nsname, mac))
        return ifname_master

    def create_interface(self, nsname, ifname_instance, vmi=None):
        ifname_master = self._interface_generate_unique_name()
        shell_command('ip link add %s type veth peer name %s' %
                      (ifname_instance, ifname_master))
        if vmi:
            mac = vmi.virtual_machine_interface_mac_addresses.mac_address[0]
            shell_command('ifconfig %s hw ether %s' % (ifname_instance,mac))

        shell_command('ip link set %s netns %s' % (ifname_instance, nsname))
        shell_command('ip link set %s up' % ifname_master)
        return ifname_master

    def _interface_list_contains(self, output, iface):
        for line in output.split('\n'):
            m = re.match(r'[\d]+: ' + iface + ':', line)
            if m:
                return True
        return False

    def _get_master_ifname(self, daemon, ifname_instance):
        output = shell_command('ip netns exec ns-%s ethtool -S %s' %
                               (daemon, ifname_instance))
        m = re.search(r'peer_ifindex: (\d+)', output)
        ifindex = m.group(1)
        output = shell_command('ip link list')
        expr = '^' + ifindex + ': (\w+): '
        regex = re.compile(expr, re.MULTILINE)
        m = regex.search(output)
        return m.group(1)

    def interface_update(self, daemon, vmi, ifname_instance):
        """
        1. Make sure that the interface exists in the name space.
        2. Update the mac address.
        """
        output = shell_command('ip netns exec ns-%s ip link list' % daemon)
        if not self._interface_list_contains(output, ifname_instance):
            ifname_master = self.create_interface('ns-%s' % daemon, ifname_instance)
        else:
            ifname_master = self._get_master_ifname(daemon, ifname_instance)

        mac = vmi.virtual_machine_interface_mac_addresses.mac_address[0]
        shell_command('ip netns exec ns-%s ifconfig %s hw ether %s' %
                      (daemon, ifname_instance, mac))
        return ifname_master

    def interface_config(self, daemon, ifname_guest, advertise_default=True,
                         ip_prefix=None):
        """
        Once the interface is operational, configure the IP addresses.
        For a bi-directional interface we use dhclient.
        """
        if advertise_default:
            shell_command('ip netns exec ns-%s dhclient %s' %
                          (daemon, ifname_guest))
        else:
            shell_command('ip netns exec ns-%s ip addr add %s/%d dev %s' %
                          (daemon, ip_prefix[0], ip_prefix[1], ifname_guest))
            shell_command('ip netns exec ns-%s ip link set %s up' %
                          (daemon, ifname_guest))
            # disable reverse path filtering
            shell_command('ip netns exec ns-%s sh -c ' +
                          '"echo 2 >/proc/sys/net/ipv4/conf/%s/rp_filter"' %
                          (daemon, ifname_guest))

    def clear_interfaces(self, nsname):
        shell_command('ip netns exec %s dhclient -r' % nsname)
        output = shell_command('ip netns exec %s ip link list' % nsname)
        for line in output.split('\n'):
            m = re.match(r'^[\d]+: ([\w]+):', line)
            if m:
                ifname = m.group(1)
                if ifname == 'lo':
                    continue
                shell_command('ip netns exec %s ip link delete %s' %
                              (nsname, ifname))

    def namespace_init(self, daemon):
        output = shell_command('ip netns list')
        for line in output.split():
            if line == 'ns-' + daemon:
                return False
        shell_command('ip netns add ns-%s' % daemon)
        return True

    def namespace_delete(self, daemon):
        shell_command('ip netns delete ns-%s' % daemon)
