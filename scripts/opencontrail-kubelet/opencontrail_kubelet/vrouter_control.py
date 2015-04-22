
from contrail_vrouter_api.vrouter_api import ContrailVRouterApi

def interface_register(vmId, vmi, iface_name):
    api = ContrailVRouterApi()
    mac = vmi.virtual_machine_interface_mac_addresses.mac_address[0]
    api.add_port(vmId, vmi.uuid, iface_name, mac, port_type='NovaVMPort')


def interface_unregister(vmi_uuid):
    api = ContrailVRouterApi()
    api.delete_port(vmi_uuid)
