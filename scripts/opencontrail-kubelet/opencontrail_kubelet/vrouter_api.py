#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import json
import logging
import requests


VROUTER_AGENT_PORT = 9091


class ContrailVRouterApi(object):
    def __init__(self):
        pass

    def add_port(self, instanceId, nicId, sysIfName, macAddress, **kwargs):
        data = {
            "id": nicId,
            "instance-id": instanceId,
            "system-name": sysIfName,
            "mac-address": macAddress,
            "vn-id": "00000000-0000-0000-0000-000000000001",
            "vm-project-id": "00000000-0000-0000-0000-000000000001",
            "ip-address": "0.0.0.0",
            "ip6-address": "0::0",
            "rx-vlan-id": 0,
            "tx-vlan-id": 0,
            "type": 0
        }

        if 'display_name' in kwargs:
            data['display-name'] = kwargs['display_name']
        if 'port_type' in kwargs:
            if kwargs['port_type'] == "NovaVMPort":
                data['type'] = 0
            if kwargs['port_type'] == "NameSpacePort":
                data['type'] = 1

        json_data = json.dumps(data)

        url = "http://localhost:%d/port" % (VROUTER_AGENT_PORT)
        headers = {'content-type': 'application/json'}
        r = requests.post(url, data=json_data, headers=headers)
        if r.status_code != requests.codes.ok:
            logging.error("%s: %s", url, r.text)

    def delete_port(self, nicId):
        url = "http://localhost:%d/port/%s" % (VROUTER_AGENT_PORT, nicId)
        headers = {'content-type': 'application/json'}
        r = requests.delete(url, data=None, headers=headers)
        if r.status_code != requests.codes.ok:
            logging.error("%s: %s", url, r.headers['status'])
