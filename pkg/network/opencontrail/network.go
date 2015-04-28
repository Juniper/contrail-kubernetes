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

type NetworkManager struct {
	client *contrail.Client
	config *Config
}

func NewNetworkManager(client *contrail.Client, config *Config) *NetworkManager {
	manager := new(NetworkManager)
	manager.client = client
	manager.config = config
	manager.initializePublicNetwork()
	return manager
}

func (m *NetworkManager) LocateFloatingIpPool(
	network *types.VirtualNetwork, name, subnet string) *types.FloatingIpPool {
	fqn := network.GetFQName()
	fqn = AppendConst(fqn[0:len(fqn)-1], name)
	obj, err := m.client.FindByName(
		"floating-ip-pool", strings.Join(fqn, ":"))
	if err == nil {
		return obj.(*types.FloatingIpPool)
	}

	address, prefixlen := PrefixToAddressLen(subnet)

	pool := new(types.FloatingIpPool)
	pool.SetName(name)
	pool.SetParent(network)
	pool.SetFloatingIpPoolPrefixes(
		&types.FloatingIpPoolType{
			Subnet: []types.SubnetType{types.SubnetType{address, prefixlen}}})
	err = m.client.Create(pool)
	if err != nil {
		glog.Errorf("Create floating-ip-pool %s: %v", name, err)
		return nil
	}
	return pool
}

func (m *NetworkManager) initializePublicNetwork() {
	var network *types.VirtualNetwork
	obj, err := m.client.FindByName("virtual-network", m.config.PublicNetwork)
	if err != nil {
		fqn := strings.Split(m.config.PublicNetwork, ":")
		parent := strings.Join(fqn[0:len(fqn)-1], ":")
		projectId, err := m.client.UuidByName("project", parent)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		networkId, err := config.CreateNetworkWithSubnet(
			m.client, projectId, m.config.PublicNetwork, m.config.PublicSubnet)
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

	// TODO(prm): Ensure that the subnet is as specified.
	m.LocateFloatingIpPool(network, m.config.PublicNetwork, m.config.PublicSubnet)
}

func (m *NetworkManager) LookupNetwork(projectName, networkName string) *types.VirtualNetwork {
	fqn := strings.Split(projectName, ":")
	fqn = AppendConst(fqn, networkName)
	obj, err := m.client.FindByName("virtual-network", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("GET virtual-network %s: %v", networkName, err)
		return nil
	}
	return obj.(*types.VirtualNetwork)
}

func (m *NetworkManager) LocateNetwork(project, name, subnet string) *types.VirtualNetwork {
	fqn := append(strings.Split(project, ":"), name)
	fqname := strings.Join(fqn, ":")

	obj, err := m.client.FindByName("virtual-network", fqname)
	if err == nil {
		return obj.(*types.VirtualNetwork)
	}

	projectId, err := m.client.UuidByName("project", project)
	if err != nil {
		glog.Infof("GET %s: %v", project, err)
		return nil
	}
	uid, err := config.CreateNetworkWithSubnet(
		m.client, projectId, name, subnet)
	if err != nil {
		glog.Infof("Create %s: %v", name, err)
		return nil
	}
	obj, err = m.client.FindByUuid("virtual-network", uid)
	if err != nil {
		glog.Infof("GET %s: %v", name, err)
		return nil
	}
	glog.Infof("Create network %s", fqname)
	return obj.(*types.VirtualNetwork)
}

func (m *NetworkManager) ReleaseNetworkIfEmpty(namespace, name string) {
	fqn := []string{DefaultDomain, namespace, name}
	obj, err := m.client.FindByName("virtual-network", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("Get virtual-network %s: %v", name, err)
		return
	}
	network := obj.(*types.VirtualNetwork)
	refs, err := network.GetVirtualMachineInterfaceBackRefs()
	if err != nil {
		glog.Errorf("Get network vmi references %s: %v", name, err)
		return
	}
	if len(refs) == 0 {
		err = m.client.Delete(network)
		if err != nil {
			glog.Errorf("Delete virtual-network %s: %v", name, err)
		}
	}
}

func (m *NetworkManager) LocateFloatingIp(networkName, resourceName, address string) *types.FloatingIp {
	poolName := fmt.Sprintf("%s:%s", DefaultProject, networkName)
	obj, err := m.client.FindByName("floating-ip-pool", poolName)
	if err != nil {
		glog.Errorf("Get floating-ip-pool %s: %v", poolName, err)
		return nil
	}
	pool := obj.(*types.FloatingIpPool)

	fqn := AppendConst(pool.GetFQName(), resourceName)
	obj, err = m.client.FindByName("floating-ip", strings.Join(fqn, ":"))
	if err == nil {
		fip := obj.(*types.FloatingIp)
		if fip.GetFloatingIpAddress() != address {
			fip.SetFloatingIpAddress(address)
			err = m.client.Update(fip)
			if err != nil {
				glog.Errorf("Update floating-ip %s: %v", resourceName, err)
				return nil
			}
		}
		return fip
	}

	obj, err = m.client.FindByName("project", DefaultProject)
	if err != nil {
		glog.Errorf("Get project %s: %v", DefaultProject, err)
		return nil
	}
	project := obj.(*types.Project)

	fip := new(types.FloatingIp)
	fip.SetParent(pool)
	fip.SetName(resourceName)
	fip.SetFloatingIpAddress(address)
	fip.AddProject(project)
	err = m.client.Create(fip)
	if err != nil {
		glog.Errorf("Create floating-ip %s: %v", resourceName, err)
		return nil
	}
	return fip
}

func (m *NetworkManager) GetGatewayAddress(network *types.VirtualNetwork) (string, error) {
	return "", nil
}
