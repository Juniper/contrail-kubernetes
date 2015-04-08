#
# Copyright (c) 2015 Juniper Networks, Inc.
#

import mock
import unittest

from opencontrail_kubelet.plugin import ContrailClient

class PluginTest(unittest.TestCase):
    _IP_ADDR_OUTPUT = """\
8: vhost0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 02:3a:2a:df:16:ed brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.3/24 scope global vhost0
       valid_lft forever preferred_lft forever
    inet6 fe80::3a:2aff:fedf:16ed/64 scope link 
       valid_lft forever preferred_lft forever
"""

    @mock.patch('opencontrail_kubelet.plugin.ContrailClient.__init__',
                mock.Mock(return_value=None))
    def test_local_address(self):
        client = ContrailClient()
        with mock.patch('opencontrail_kubelet.plugin.subprocess') as subprocess:
            subprocess.check_output.return_value.returncode = 0
            subprocess.check_output.return_value = PluginTest._IP_ADDR_OUTPUT
            self.assertEqual('192.168.1.3', client.local_address())
