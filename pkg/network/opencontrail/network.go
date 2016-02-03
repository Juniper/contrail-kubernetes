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
	"strings"

	"github.com/golang/glog"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/config"
	"github.com/Juniper/contrail-go-api/types"
)

type NetworkManager interface {
	LocateFloatingIpPool(network *types.VirtualNetwork, subnet string) (*types.FloatingIpPool, error)
	LookupFloatingIpPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error)
	DeleteFloatingIpPool(network *types.VirtualNetwork, cascade bool) error
	LookupNetwork(projectName, networkName string) (*types.VirtualNetwork, error)
	LocateNetwork(project, name, subnet string) (*types.VirtualNetwork, error)
	DeleteNetwork(*types.VirtualNetwork) error
	ReleaseNetworkIfEmpty(namespace, name string) (bool, error)
	LocateFloatingIp(network *types.VirtualNetwork, resourceName, address string) (*types.FloatingIp, error)
	DeleteFloatingIp(network *types.VirtualNetwork, resourceName string) error
	GetPublicNetwork() *types.VirtualNetwork
	GetGatewayAddress(network *types.VirtualNetwork) (string, error)
}

type NetworkManagerImpl struct {
	client        contrail.ApiClient
	config        *Config
	publicNetwork *types.VirtualNetwork
}

func NewNetworkManager(client contrail.ApiClient, config *Config) NetworkManager {
	manager := new(NetworkManagerImpl)
	manager.client = client
	manager.config = config
	manager.initializePublicNetwork()
	return manager
}

func (m *NetworkManagerImpl) GetPublicNetwork() *types.VirtualNetwork {
	return m.publicNetwork
}

func makePoolName(network *types.VirtualNetwork) string {
	fqn := make([]string, len(network.GetFQName()), len(network.GetFQName())+1)
	copy(fqn, network.GetFQName())
	fqn = append(fqn, fqn[len(fqn)-1])
	return strings.Join(fqn, ":")
}

func (m *NetworkManagerImpl) LocateFloatingIpPool(
	network *types.VirtualNetwork, subnet string) (*types.FloatingIpPool, error) {
	obj, err := m.client.FindByName(
		"floating-ip-pool", makePoolName(network))
	if err == nil {
		return obj.(*types.FloatingIpPool), nil
	}

	address, prefixlen := PrefixToAddressLen(subnet)

	pool := new(types.FloatingIpPool)
	pool.SetName(network.GetName())
	pool.SetParent(network)
	pool.SetFloatingIpPoolPrefixes(
		&types.FloatingIpPoolType{
			Subnet: []types.SubnetType{types.SubnetType{address, prefixlen}}})
	err = m.client.Create(pool)
	if err != nil {
		glog.Errorf("Create floating-ip-pool %s: %v", network.GetName(), err)
		return nil, err
	}
	return pool, nil
}

func (m *NetworkManagerImpl) LookupFloatingIpPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error) {
	pool, err := types.FloatingIpPoolByName(m.client, makePoolName(network))
	return pool, err
}

func (m *NetworkManagerImpl) floatingIpPoolDeleteChildren(pool *types.FloatingIpPool) error {
	fips, err := pool.GetFloatingIps()
	if err != nil {
		glog.Errorf("Get floating-ip-pool %s: %v", pool.GetName(), err)
		return err
	}
	for _, fip := range fips {
		err := m.client.DeleteByUuid("floating-ip", fip.Uuid)
		if err != nil {
			glog.Errorf("Delete floating-ip %s: %v", fip.Uuid, err)
		}
	}
	return nil
}
func (m *NetworkManagerImpl) DeleteFloatingIpPool(network *types.VirtualNetwork, cascade bool) error {
	obj, err := m.client.FindByName("floating-ip-pool", makePoolName(network))
	if err != nil {
		glog.Errorf("Get floating-ip-pool %s: %v", network.GetName(), err)
		return err
	}
	if cascade {
		pool := obj.(*types.FloatingIpPool)
		m.floatingIpPoolDeleteChildren(pool)
	}
	m.client.Delete(obj)
	return nil
}

func (m *NetworkManagerImpl) initializePublicNetwork() {
	var network *types.VirtualNetwork
	obj, err := m.client.FindByName("virtual-network", m.config.PublicNetwork)
	if err != nil {
		fqn := strings.Split(m.config.PublicNetwork, ":")
		parent := strings.Join(fqn[0:len(fqn)-1], ":")
		projectId, err := m.client.UuidByName("project", parent)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		var networkId string
		networkName := fqn[len(fqn)-1]
		if len(m.config.PublicSubnet) > 0 {
			networkId, err = config.CreateNetworkWithSubnet(
				m.client, projectId, networkName, m.config.PublicSubnet)
		} else {
			networkId, err = config.CreateNetwork(m.client, projectId, networkName)
		}
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}

		glog.Infof("Created network %s", m.config.PublicNetwork)

		obj, err := m.client.FindByUuid("virtual-network", networkId)
		if err != nil {
			glog.Fatalf("GET %s %v", networkId, err)
		}
		network = obj.(*types.VirtualNetwork)
	} else {
		network = obj.(*types.VirtualNetwork)
	}

	m.publicNetwork = network

	// TODO(prm): Ensure that the subnet is as specified.
	if len(m.config.PublicSubnet) > 0 {
		m.LocateFloatingIpPool(network, m.config.PublicSubnet)
	}
}

func (m *NetworkManagerImpl) LookupNetwork(projectName, networkName string) (*types.VirtualNetwork, error) {
	fqn := []string{m.config.DefaultDomain, projectName, networkName}
	obj, err := m.client.FindByName("virtual-network", strings.Join(fqn, ":"))
	if err != nil {
		glog.V(3).Infof("GET virtual-network %s: %v", networkName, err)
		return nil, err
	}
	return obj.(*types.VirtualNetwork), nil
}

func (m *NetworkManagerImpl) LocateNetwork(project, name, subnet string) (*types.VirtualNetwork, error) {
	fqn := []string{m.config.DefaultDomain, project, name}
	fqname := strings.Join(fqn, ":")

	obj, err := m.client.FindByName("virtual-network", fqname)
	if err == nil {
		return obj.(*types.VirtualNetwork), nil
	}

	projectId, err := m.client.UuidByName("project", fmt.Sprintf("%s:%s", m.config.DefaultDomain, project))
	if err != nil {
		glog.Infof("GET %s: %v", project, err)
		return nil, err
	}
	uid, err := config.CreateNetworkWithSubnet(
		m.client, projectId, name, subnet)
	if err != nil {
		glog.Infof("Create %s: %v", name, err)
		return nil, err
	}
	obj, err = m.client.FindByUuid("virtual-network", uid)
	if err != nil {
		glog.Infof("GET %s: %v", name, err)
		return nil, err
	}
	glog.Infof("Create network %s", fqname)
	return obj.(*types.VirtualNetwork), nil
}

func (m *NetworkManagerImpl) ReleaseNetworkIfEmpty(namespace, name string) (bool, error) {
	fqn := []string{m.config.DefaultDomain, namespace, name}
	obj, err := m.client.FindByName("virtual-network", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("Get virtual-network %s: %v", name, err)
		return false, err
	}
	network := obj.(*types.VirtualNetwork)
	refs, err := network.GetVirtualMachineInterfaceBackRefs()
	if err != nil {
		glog.Errorf("Get network vmi references %s: %v", name, err)
		return false, err
	}
	if len(refs) == 0 {
		err = m.client.Delete(network)
		if err != nil {
			glog.Errorf("Delete virtual-network %s: %v", name, err)
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (m *NetworkManagerImpl) LocateFloatingIp(network *types.VirtualNetwork, resourceName, targetAddress string) (*types.FloatingIp, error) {
	obj, err := m.client.FindByName("floating-ip-pool", makePoolName(network))
	if err != nil {
		glog.Errorf("Get floating-ip-pool %s: %v", network.GetName(), err)
		return nil, err
	}
	pool := obj.(*types.FloatingIpPool)

	fqn := AppendConst(pool.GetFQName(), resourceName)
	obj, err = m.client.FindByName("floating-ip", strings.Join(fqn, ":"))
	if err == nil {
		fip := obj.(*types.FloatingIp)
		if targetAddress != "" && fip.GetFloatingIpAddress() != targetAddress {
			fip.SetFloatingIpAddress(targetAddress)
			err = m.client.Update(fip)
			if err != nil {
				glog.Errorf("Update floating-ip %s: %v", resourceName, err)
				return nil, err
			}
		}
		return fip, nil
	}

	projectFQN := network.GetFQName()[0 : len(network.GetFQName())-1]
	obj, err = m.client.FindByName("project", strings.Join(projectFQN, ":"))
	if err != nil {
		glog.Errorf("Get project %s: %v", projectFQN[len(projectFQN)-1], err)
		return nil, err
	}
	project := obj.(*types.Project)

	fip := new(types.FloatingIp)
	fip.SetParent(pool)
	fip.SetName(resourceName)
	if targetAddress != "" {
		fip.SetFloatingIpAddress(targetAddress)
	}
	fip.AddProject(project)
	err = m.client.Create(fip)
	if err != nil {
		glog.Errorf("Create floating-ip %s: %v", resourceName, err)
		return nil, err
	}
	if targetAddress == "" {
		fip, err = types.FloatingIpByUuid(m.client, fip.GetUuid())
	}
	return fip, err
}

func (m *NetworkManagerImpl) DeleteFloatingIp(network *types.VirtualNetwork, resourceName string) error {
	name := fmt.Sprintf("%s:%s", makePoolName(network), resourceName)
	obj, err := m.client.FindByName("floating-ip", name)
	if err != nil {
		return err
	}
	return m.client.Delete(obj)
}

func (m *NetworkManagerImpl) GetGatewayAddress(network *types.VirtualNetwork) (string, error) {
	refs, err := network.GetNetworkIpamRefs()
	if err != nil {
		glog.Errorf("Get network %s network-ipam refs: %v", network.GetName(), err)
		return "", err
	}

	attr := refs[0].Attr.(types.VnSubnetsType)
	if len(attr.IpamSubnets) == 0 {
		glog.Errorf("Network %s has no subnets configured", network.GetName())
		return "", fmt.Errorf("Network %s: empty subnet list", network.GetName())
	}

	gateway := attr.IpamSubnets[0].DefaultGateway
	if gateway == "" {
		glog.Errorf("Gateway for %s is empty", network.GetName())
		return "", fmt.Errorf("Gateway is empty: %+v", attr.IpamSubnets)
	}

	return gateway, nil
}

func (m *NetworkManagerImpl) DeleteNetwork(network *types.VirtualNetwork) error {
	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		glog.Errorf("Get %s policy refs: %v", network.GetName(), err)
	}
	m.client.Delete(network)

	for _, ref := range refs {
		obj, err := m.client.FindByUuid("network-policy", ref.Uuid)
		if err != nil {
			glog.Errorf("Get policy %s: %v", ref.Uuid, err)
		}
		policy := obj.(*types.NetworkPolicy)
		npRefs, err := policy.GetVirtualNetworkBackRefs()
		if len(npRefs) == 0 {
			m.client.Delete(policy)
		}
	}
	return nil
}
