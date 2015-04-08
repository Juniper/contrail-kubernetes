"""
"""

from vnc_api.vnc_api import *


class Provisioner(object):
    def __init__(self, api_server='127.0.0.1', api_port=8082,
                 project='default-domain:default-project'):
        self._client = VncApi(api_server_host=api_server,
                              api_server_port=api_port)
        self._project = project

    def virtual_machine_lookup(self, vm_name):
        fq_name = [vm_name]
        try:
            vm_instance = self._client.virtual_machine_read(fq_name=fq_name)
            return vm_instance
        except NoIdError:
            pass
        return None

    def virtual_machine_locate(self, vm_name):
        # if vm_name.find(':') == -1:
        #    vm_name = self._project + ':' + vm_name
        fq_name = vm_name.split(':')
        try:
            vm_instance = self._client.virtual_machine_read(fq_name=fq_name)
            return vm_instance
        except NoIdError:
            pass

        vm_instance = VirtualMachine(vm_name)
        self._client.virtual_machine_create(vm_instance)
        return vm_instance

    def virtual_machine_delete(self, vm_instance):
        self._client.virtual_machine_delete(id=vm_instance.uuid)

    def vmi_locate(self, vm_instance, network, name, advertise_default=True):
        fq_name = vm_instance.fq_name[:]
        fq_name.append(name)
        create = False
        try:
            vmi = self._client.virtual_machine_interface_read(fq_name=fq_name)
        except NoIdError:
            vmi = VirtualMachineInterface(parent_type='virtual-machine',
                                          fq_name=fq_name)
            create = True

        vmi.set_virtual_network(network)
        if create:
            self._client.virtual_machine_interface_create(vmi)
            vmi = self._client.virtual_machine_interface_read(id=vmi.uuid)
        else:
            self._client.virtual_machine_interface_update(vmi)

        ips = vmi.get_instance_ip_back_refs()
        if ips and len(ips):
            uuid = ips[0]['uuid']
        else:
            ip = InstanceIp(vm_instance.name + '.' + name)
            ip.set_virtual_machine_interface(vmi)
            ip.set_virtual_network(network)
            uuid = self._client.instance_ip_create(ip)

        ip = self._client.instance_ip_read(id=uuid)

        # print "IP address: %s" % ip.get_instance_ip_address()
        return vmi

    def vmi_delete(self, uuid):
        try:
            vmi = self._client.virtual_machine_interface_read(id=uuid)
        except NoIdError:
            return

        ips = vmi.get_instance_ip_back_refs()
        for ref in ips:
            self._client.instance_ip_delete(id=ref['uuid'])

        self._client.virtual_machine_interface_delete(id=vmi.uuid)

    def _get_vmi_prefixlen(self, vmi):
        refs = vmi.get_virtual_network_refs()
        if len(refs) == 0:
            sys.exit(1)

        vnet = self._client.virtual_network_read(id=refs[0]['uuid'])
        ipam_r = vnet.get_network_ipam_refs()
        return ipam_r[0]['attr'].ipam_subnets[0].subnet.ip_prefix_len

    def get_interface_ip_prefix(self, vmi):
        ips = vmi.get_instance_ip_back_refs()
        if len(ips) == 0:
            return None
        ip_obj = self._client.instance_ip_read(id=ips[0]['uuid'])
        ip_addr = ip_obj.get_instance_ip_address()
        ip_prefixlen = self._get_vmi_prefixlen(vmi)
        return (ip_addr, ip_prefixlen)
