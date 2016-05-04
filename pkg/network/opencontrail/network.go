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
	"regexp"
	"strings"

	"github.com/golang/glog"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/config"
	"github.com/Juniper/contrail-go-api/types"
)

// NetworkManager defines the interface between the Controller and VirtualNetwork operations.
type NetworkManager interface {
	LocateFloatingIPPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error)
	LookupFloatingIPPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error)
	DeleteFloatingIPPool(network *types.VirtualNetwork, cascade bool) error
	LookupNetwork(projectName, networkName string) (*types.VirtualNetwork, error)
	LocateNetwork(project, name, subnet string) (*types.VirtualNetwork, error)
	DeleteNetwork(*types.VirtualNetwork) error
	ReleaseNetworkIfEmpty(namespace, name string) (bool, error)
	LocateFloatingIP(network *types.VirtualNetwork, resourceName, address string) (*types.FloatingIp, error)
	DeleteFloatingIP(network *types.VirtualNetwork, resourceName string) error
	GetPublicNetwork() *types.VirtualNetwork
	GetGatewayAddress(network *types.VirtualNetwork) (string, error)
	Connect(network *types.VirtualNetwork, targetCSN string) error
	Disconnect(networkFQN []string, targetCSN string) error
	DeleteConnections(network *types.VirtualNetwork, policies map[string]string) error
}

type networkManagerImpl struct {
	client        contrail.ApiClient
	config        *Config
	publicNetwork *types.VirtualNetwork
}

// NewNetworkManager allocates an implementation of the NetworkManager interface
func NewNetworkManager(client contrail.ApiClient, config *Config) NetworkManager {
	manager := new(networkManagerImpl)
	manager.client = client
	manager.config = config
	if config.PublicSubnet != "" {
		manager.initializePublicNetwork()
	}
	return manager
}

func (m *networkManagerImpl) GetPublicNetwork() *types.VirtualNetwork {
	return m.publicNetwork
}

func makePoolName(network *types.VirtualNetwork) string {
	fqn := make([]string, len(network.GetFQName()), len(network.GetFQName())+1)
	copy(fqn, network.GetFQName())
	fqn = append(fqn, fqn[len(fqn)-1])
	return strings.Join(fqn, ":")
}

func (m *networkManagerImpl) LocateFloatingIPPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error) {
	obj, err := m.client.FindByName("floating-ip-pool", makePoolName(network))
	if err == nil {
		return obj.(*types.FloatingIpPool), nil
	}

	pool := new(types.FloatingIpPool)
	pool.SetName(network.GetName())
	pool.SetParent(network)
	err = m.client.Create(pool)
	if err != nil {
		glog.Errorf("Create floating-ip-pool %s: %v", network.GetName(), err)
		return nil, err
	}
	return pool, nil
}

func (m *networkManagerImpl) LookupFloatingIPPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error) {
	pool, err := types.FloatingIpPoolByName(m.client, makePoolName(network))
	return pool, err
}

func (m *networkManagerImpl) floatingIPPoolDeleteChildren(pool *types.FloatingIpPool) error {
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
func (m *networkManagerImpl) DeleteFloatingIPPool(network *types.VirtualNetwork, cascade bool) error {
	obj, err := m.client.FindByName("floating-ip-pool", makePoolName(network))
	if err != nil {
		glog.Errorf("Get floating-ip-pool %s: %v", network.GetName(), err)
		return err
	}
	if cascade {
		pool := obj.(*types.FloatingIpPool)
		m.floatingIPPoolDeleteChildren(pool)
	}
	m.client.Delete(obj)
	return nil
}

// Subnets can only be deleted if there are no instance-ips or floating-ips associated
// with the subnet.
func (m *networkManagerImpl) updateSubnetConfig(network *types.VirtualNetwork, prefix string) error {
	prefixList, err := m.NetworkIPPrefixList(network)
	if err != nil {
		glog.Fatal(err)
	}
	add := true
	for _, pfx := range prefixList {
		if pfx == prefix {
			add = false
			continue
		}

		ipRefs, err := network.GetInstanceIpBackRefs()
		if err != nil {
			glog.Error(err)
			continue
		}

		// TODO: filter the IP addresses associated with the subnet that we are
		// attempting to delete.
		if len(ipRefs) > 0 {
			glog.Warningf(
				"network %s %s is stale but there are %d instance-ips present",
				network.GetName(), pfx, len(ipRefs))
			continue
		}

		pool, err := m.LookupFloatingIPPool(network)
		if err == nil {
			floatRefs, err := pool.GetFloatingIps()
			if err != nil {
				glog.Error(err)
				continue
			}
			// TODO: filter the floating-ips associated with the subnet that we
			// are attempting to delete.
			if len(floatRefs) > 0 {
				glog.Warningf(
					"network %s %s is stale but there are %d floating-ip addresses present",
					network.GetName(), pfx, len(floatRefs))
				continue
			}
		}

		err = config.RemoveSubnet(m.client, network, pfx)
		if err != nil {
			glog.Error(err)
		}
	}
	if add {
		_, err := config.AddSubnet(m.client, network, m.config.PublicSubnet)
		if err != nil {
			glog.Error(err)
		}
		return err
	}
	return nil
}

func (m *networkManagerImpl) initializePublicNetwork() {
	var network *types.VirtualNetwork
	obj, err := m.client.FindByName("virtual-network", m.config.PublicNetwork)
	if err != nil {
		fqn := strings.Split(m.config.PublicNetwork, ":")
		parent := strings.Join(fqn[0:len(fqn)-1], ":")
		projectID, err := m.client.UuidByName("project", parent)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		var networkID string
		networkName := fqn[len(fqn)-1]
		networkID, err = config.CreateNetworkWithSubnet(
			m.client, projectID, networkName, m.config.PublicSubnet)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}

		glog.Infof("Created network %s", m.config.PublicNetwork)

		obj, err := m.client.FindByUuid("virtual-network", networkID)
		if err != nil {
			glog.Fatalf("GET %s %v", networkID, err)
		}
		network = obj.(*types.VirtualNetwork)
	} else {
		network = obj.(*types.VirtualNetwork)
		m.updateSubnetConfig(network, m.config.PublicSubnet)
	}

	m.publicNetwork = network

	m.LocateFloatingIPPool(network)
}

func (m *networkManagerImpl) LookupNetwork(projectName, networkName string) (*types.VirtualNetwork, error) {
	fqn := []string{m.config.DefaultDomain, projectName, networkName}
	obj, err := m.client.FindByName("virtual-network", strings.Join(fqn, ":"))
	if err != nil {
		glog.V(3).Infof("GET virtual-network %s: %v", networkName, err)
		return nil, err
	}
	return obj.(*types.VirtualNetwork), nil
}

// LocateNetwork creates a private network.
//
// It is used to create pod and service networks.
func (m *networkManagerImpl) LocateNetwork(project, name, subnet string) (*types.VirtualNetwork, error) {
	fqn := []string{m.config.DefaultDomain, project, name}
	fqname := strings.Join(fqn, ":")

	obj, err := m.client.FindByName("virtual-network", fqname)
	if err == nil {
		return obj.(*types.VirtualNetwork), nil
	}

	projectID, err := m.client.UuidByName("project", fmt.Sprintf("%s:%s", m.config.DefaultDomain, project))
	if err != nil {
		glog.Infof("GET %s: %v", project, err)
		return nil, err
	}
	uid, err := config.CreateNetworkWithSubnet(m.client, projectID, name, subnet)
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

func (m *networkManagerImpl) ReleaseNetworkIfEmpty(namespace, name string) (bool, error) {
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
		glog.V(3).Infof("Delete network %s", name)
		return true, nil
	}
	return false, nil
}

func (m *networkManagerImpl) LocateFloatingIP(network *types.VirtualNetwork, resourceName, targetAddress string) (*types.FloatingIp, error) {
	obj, err := m.client.FindByName("floating-ip-pool", makePoolName(network))
	if err != nil {
		glog.Errorf("Get floating-ip-pool %s: %v", network.GetName(), err)
		return nil, err
	}
	pool := obj.(*types.FloatingIpPool)

	fqn := appendConst(pool.GetFQName(), resourceName)
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

func (m *networkManagerImpl) DeleteFloatingIP(network *types.VirtualNetwork, resourceName string) error {
	name := fmt.Sprintf("%s:%s", makePoolName(network), resourceName)
	obj, err := m.client.FindByName("floating-ip", name)
	if err != nil {
		return err
	}
	return m.client.Delete(obj)
}

func (m *networkManagerImpl) GetGatewayAddress(network *types.VirtualNetwork) (string, error) {
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

func (m *networkManagerImpl) DeleteNetwork(network *types.VirtualNetwork) error {
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

//
// Retrieve the list of IP prefixes associated with this network.
//
func (m *networkManagerImpl) NetworkIPPrefixList(network *types.VirtualNetwork) ([]string, error) {
	var prefixList []string
	refList, err := network.GetNetworkIpamRefs()
	if err != nil {
		return nil, err
	}

	for _, ref := range refList {
		attr := ref.Attr.(types.VnSubnetsType)
		for _, ipamSubnet := range attr.IpamSubnets {
			prefixList = append(prefixList,
				fmt.Sprintf("%s/%d", ipamSubnet.Subnet.IpPrefix, ipamSubnet.Subnet.IpPrefixLen))
		}
	}

	return prefixList, nil
}

func makeGlobalNetworkPolicyName(config *Config, targetName []string) []string {
	if targetName[0] == config.DefaultDomain {
		return []string{config.DefaultDomain, targetName[1], networkPolicyPrefix + targetName[2]}
	}
	name := networkPolicyPrefix + strings.Join(escapeFQN(targetName), "_")
	return []string{config.DefaultDomain, config.DefaultProject, name}
}

func globalNetworkFromPolicyName(config *Config, policyName []string) (string, error) {
	if len(policyName) != 3 {
		return "", fmt.Errorf("Invalid name for policy object")
	}
	if !strings.HasPrefix(policyName[2], networkPolicyPrefix) {
		return "", fmt.Errorf("Not a global-network policy")
	}
	networkName := policyName[2][len(networkPolicyPrefix):]
	if policyName[0] == config.DefaultDomain {
		networkFQN := []string{config.DefaultDomain, policyName[1], networkName}
		return strings.Join(networkFQN, ":"), nil
	}
	networkFQN := splitEscapedString(networkName)
	return strings.Join(networkFQN, ":"), nil
}

func (m *networkManagerImpl) locatePolicy(targetName []string) (*types.NetworkPolicy, error) {
	policyName := makeGlobalNetworkPolicyName(m.config, targetName)
	policy, err := types.NetworkPolicyByName(m.client, strings.Join(policyName, ":"))
	if err != nil {
		policy = new(types.NetworkPolicy)
		policy.SetFQName("project", policyName)
		err = m.client.Create(policy)
	}
	return policy, err
}

// Connect creates a network-policy and corresponding policy rule (when they do not exist) in order to
// connect the source network with the target. The target network may or not exist yet.
func (m *networkManagerImpl) Connect(network *types.VirtualNetwork, targetCSN string) error {
	targetName := strings.Split(targetCSN, ":")
	policy, err := m.locatePolicy(targetName)
	if err != nil {
		return err
	}

	policyAttach(m.client, network, policy)

	target, err := types.VirtualNetworkByName(m.client, targetCSN)
	if err == nil {
		err = policyAttach(m.client, target, policy)
		if err != nil {
			glog.Error(err)
		}
	}

	err = policyLocateRuleByFQN(m.client, policy, network.GetFQName(), targetName)
	if err != nil {
		return err
	}
	return nil
}

func (m *networkManagerImpl) disconnectNetworkFromPolicy(policy *types.NetworkPolicy, targetCSN string) error {
	target, err := types.VirtualNetworkByName(m.client, targetCSN)
	if err != nil {
		return err
	}
	err = target.DeleteNetworkPolicy(policy.GetUuid())
	if err != nil {
		return err
	}
	return m.client.Update(target)
}

// Disconnect is called after the virtual network is deleted.
// The corresponding rule should be removed from the policy; and the policy should be
// deleted if no longer in use.
func (m *networkManagerImpl) Disconnect(networkFQN []string, targetCSN string) error {
	policy, err := m.locatePolicy(strings.Split(targetCSN, ":"))
	if err != nil {
		return err
	}

	networkRefs, err := policy.GetVirtualNetworkBackRefs()
	if err == nil {
		glog.V(3).Infof("policy %s: %d connections", policy.GetName(), len(networkRefs))
		if len(networkRefs) < 2 {
			if len(networkRefs) == 1 && strings.Join(networkRefs[0].To, ":") == targetCSN {
				err = m.disconnectNetworkFromPolicy(policy, targetCSN)
				if err != nil {
					glog.Error(err)
				}
			}
			return m.client.Delete(policy)
		}
	} else {
		glog.Error(err)
	}
	return policyDeleteRule(m.client, policy, strings.Join(networkFQN, ":"), targetCSN)
}

func isGlobalNetworkName(config *Config, networkName string) bool {
	for _, gbl := range config.GlobalNetworks {
		if gbl == networkName {
			return true
		}
	}
	return false
}

func networkAccessGlobalNetworks(config *Config, networkFQN []string) bool {
	networkName := networkFQN[1] + "/" + networkFQN[2]

	if config.GlobalConnectExclude != "" {
		re := regexp.MustCompile(config.GlobalConnectExclude)
		if re.MatchString(networkName) {
			return false
		}
	}
	if config.GlobalConnectInclude != "" {
		re := regexp.MustCompile(config.GlobalConnectInclude)
		if !re.MatchString(networkName) {
			return false
		}
	}

	return !isGlobalNetworkName(config, strings.Join(networkFQN, ":"))
}

func (m *networkManagerImpl) DeleteConnections(network *types.VirtualNetwork, policies map[string]string) error {
	for policyID := range policies {
		network.DeleteNetworkPolicy(policyID)
	}
	err := m.client.Update(network)

	for policyID, targetName := range policies {
		policy, policyErr := types.NetworkPolicyByUuid(m.client, policyID)
		if policyErr != nil {
			glog.Error(policyErr)
			continue
		}
		networkRefs, policyErr := policy.GetVirtualNetworkBackRefs()
		if len(networkRefs) > 1 {
			continue
		}
		if len(networkRefs) == 1 {
			if strings.Join(networkRefs[0].To, ":") == targetName {
				policyErr = m.disconnectNetworkFromPolicy(policy, targetName)
				if policyErr != nil {
					glog.Error(policyErr)
					continue
				}
			} else {
				continue
			}
		}
		policyErr = m.client.Delete(policy)
		if policyErr != nil {
			glog.Error(policyErr)
		}
	}

	return err
}
