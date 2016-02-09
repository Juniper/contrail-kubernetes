/*
Copyright 2015 Juniper Networks, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package opencontrail

import (
	"fmt"
	"testing"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"

	contrail_mocks "github.com/Juniper/contrail-go-api/mocks"
)

type FloatingIpInterceptor struct {
	count int
}

func (i *FloatingIpInterceptor) Put(ptr contrail.IObject) {
}

func (i *FloatingIpInterceptor) Get(ptr contrail.IObject) {
	fip := ptr.(*types.FloatingIp)
	if fip.GetFloatingIpAddress() == "" {
		i.count += 1
		fip.SetFloatingIpAddress(fmt.Sprintf("100.64.%d.%d", i.count/256, i.count&0xff))
	}
}

func TestNetworkLocate(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()

	config := new(Config)
	config.PublicNetwork = "default-domain:default-project:Public"
	netman := NewNetworkManager(client, config)

	project := new(types.Project)
	project.SetUuid(uuid.New())
	project.SetFQName("", []string{config.DefaultDomain, "p1"})
	client.Create(project)

	network, err := netman.LocateNetwork("p1", "n1", "10.0.1.0/24")
	assert.NoError(t, err, "LocateNetwork")

	n2, err := netman.LocateNetwork("p1", "n1", "10.0.1.0/24")
	assert.NoError(t, err, "LocateNetwork -- exists")
	assert.Equal(t, network, n2)
}

// The Public network subnet configuration may change.
func TestPublicNetworkSubnetChange(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()

	config := new(Config)
	config.PublicNetwork = "default-domain:default-project:Public"
	config.PublicSubnet = "192.0.2.0/24"
	netman := NewNetworkManager(client, config)

	// No public IP addresses are assigned: expect the public network to
	// have a single subnet.
	config.PublicSubnet = "198.51.100.0/24"
	netman = NewNetworkManager(client, config)

	network := netman.GetPublicNetwork()
	refs, err := network.GetNetworkIpamRefs()
	require.NoError(t, err)
	assert.Len(t, refs, 1)
	if len(refs) > 0 {
		attr := refs[0].Attr.(types.VnSubnetsType)
		assert.Len(t, attr.IpamSubnets, 1)
		if len(attr.IpamSubnets) > 0 {
			prefix := fmt.Sprintf("%s/%d",
				attr.IpamSubnets[0].Subnet.IpPrefix,
				attr.IpamSubnets[0].Subnet.IpPrefixLen)
			assert.Equal(t, config.PublicSubnet, prefix)
		}
	}
}

// When the subnet is in use it can't be deleted.
func TestPublicNetworkSubnetChangeWhenInUse(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()

	config := new(Config)
	config.PublicNetwork = "default-domain:default-project:Public"
	config.PublicSubnet = "192.0.2.0/24"
	netman := NewNetworkManager(client, config)
	_, err := netman.LocateFloatingIp(netman.GetPublicNetwork(), "test", "192.0.2.1")
	require.NoError(t, err)

	config.PublicSubnet = "198.51.100.0/24"
	netman = NewNetworkManager(client, config)

	network := netman.GetPublicNetwork()
	refs, err := network.GetNetworkIpamRefs()
	require.NoError(t, err)
	assert.Len(t, refs, 1)
	if len(refs) > 0 {
		attr := refs[0].Attr.(types.VnSubnetsType)
		assert.Len(t, attr.IpamSubnets, 2)
	}
	netman.DeleteFloatingIp(network, "test")
}
