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
	"github.com/Juniper/contrail-go-api/types"
)

type ServiceManager interface {
	Create(tenant, serviceName string) error
	Delete(tenant, serviceName string) error
	Connect(tenant, serviceName string, network *types.VirtualNetwork) error
	Disconnect(tenant, serviceName string, network *types.VirtualNetwork) error
	LocateServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error)
}

type ServiceManagerImpl struct {
	client     contrail.ApiClient
	config     *Config
	networkMgr NetworkManager
}

const (
	ServiceNetworkFmt = "service-%s"
)

func NewServiceManager(client contrail.ApiClient, config *Config, networkMgr NetworkManager) ServiceManager {
	serviceMgr := new(ServiceManagerImpl)
	serviceMgr.client = client
	serviceMgr.config = config
	serviceMgr.networkMgr = networkMgr
	return serviceMgr
}

func (m *ServiceManagerImpl) locatePolicyRule(policy *types.NetworkPolicy, rhs *types.VirtualNetwork) error {
	rhsName := strings.Join(rhs.GetFQName(), ":")

	entries := policy.GetNetworkPolicyEntries()
	for _, rule := range entries.PolicyRule {
		if rule.SrcAddresses[0].VirtualNetwork == "any" &&
			rule.DstAddresses[0].VirtualNetwork == rhsName {
			return nil
		}
	}
	rule := new(types.PolicyRuleType)
	rule.Protocol = "any"
	rule.Direction = "<>"
	rule.SrcAddresses = []types.AddressType{types.AddressType{
		VirtualNetwork: "any",
	}}
	rule.DstAddresses = []types.AddressType{types.AddressType{
		VirtualNetwork: rhsName,
	}}
	rule.SrcPorts = []types.PortType{types.PortType{-1, -1}}
	rule.DstPorts = []types.PortType{types.PortType{-1, -1}}
	rule.ActionList = &types.ActionListType{
		SimpleAction: "pass",
	}

	entries.AddPolicyRule(rule)
	policy.SetNetworkPolicyEntries(&entries)
	err := m.client.Update(policy)
	if err != nil {
		glog.Errorf("policy-rule: %v", err)
		return err
	}
	return nil
}

func (m *ServiceManagerImpl) attachPolicy(network *types.VirtualNetwork, policy *types.NetworkPolicy) error {
	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		glog.Errorf("get network policy-refs %s: %v", network.GetName(), err)
		return err
	}
	for _, ref := range refs {
		if ref.Uuid == policy.GetUuid() {
			return nil
		}
	}
	network.AddNetworkPolicy(policy,
		types.VirtualNetworkPolicyType{
			Sequence: &types.SequenceType{10, 0},
		})
	err = m.client.Update(network)
	if err != nil {
		glog.Errorf("Update network %s policies: %v", network.GetName(), err)
		return err
	}
	return nil
}

func (m *ServiceManagerImpl) detachPolicy(network *types.VirtualNetwork, policyName string) error {
	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		glog.Errorf("get network policy-refs %s: %v", network.GetName(), err)
		return err
	}
	for _, ref := range refs {
		if strings.Join(ref.To, ":") == policyName {
			network.DeleteNetworkPolicy(ref.Uuid)
			err := m.client.Update(network)
			if err != nil {
				glog.Errorf("Update network %s policies: %v", network.GetName(), err)
			}
			return err
		}
	}
	return nil
}

func (m *ServiceManagerImpl) LocateServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error) {
	networkName := fmt.Sprintf(ServiceNetworkFmt, serviceName)
	network, err := m.networkMgr.LocateNetwork(tenant, networkName, m.config.ServiceSubnet)
	if err != nil {
		return nil, err
	}
	m.networkMgr.LocateFloatingIpPool(network, m.config.ServiceSubnet)
	return network, nil
}

func (m *ServiceManagerImpl) locatePolicy(tenant, serviceName string) (*types.NetworkPolicy, error) {
	var policy *types.NetworkPolicy = nil

	fqn := []string{DefaultDomain, tenant, serviceName}
	obj, err := m.client.FindByName("network-policy", strings.Join(fqn, ":"))
	if err != nil {
		policy = new(types.NetworkPolicy)
		policy.SetFQName("project", fqn)
		err = m.client.Create(policy)
		if err != nil {
			glog.Errorf("Create policy %s: %v", strings.Join(fqn, ":"), err)
			return nil, err
		}
	} else {
		policy = obj.(*types.NetworkPolicy)
	}
	return policy, nil
}

// Attach the network to the service policy.
func (m *ServiceManagerImpl) Connect(tenant, serviceName string, network *types.VirtualNetwork) error {
	policy, err := m.locatePolicy(tenant, serviceName)
	if err != nil {
		return err
	}
	m.attachPolicy(network, policy)
	return nil
}

func (m *ServiceManagerImpl) Disconnect(tenant, serviceName string, network *types.VirtualNetwork) error {
	fqn := []string{DefaultDomain, tenant, serviceName}
	return m.detachPolicy(network, strings.Join(fqn, ":"))
}

func (m *ServiceManagerImpl) Create(tenant, serviceName string) error {
	network, err := m.LocateServiceNetwork(tenant, serviceName)
	if err != nil {
		return err
	}
	policy, err := m.locatePolicy(tenant, serviceName)
	if err != nil {
		return nil
	}
	m.locatePolicyRule(policy, network)
	m.attachPolicy(network, policy)
	return nil
}

func (m *ServiceManagerImpl) Delete(tenant, serviceName string) error {
	// Delete network
	networkName := fmt.Sprintf(ServiceNetworkFmt, serviceName)
	network, err := m.networkMgr.LookupNetwork(tenant, networkName)
	if network != nil {
		m.networkMgr.DeleteFloatingIpPool(network, true)
		m.networkMgr.DeleteNetwork(network)
	}

	// Disassociate policy
	fqn := []string{DefaultDomain, tenant, serviceName}
	obj, err := m.client.FindByName("network-policy", strings.Join(fqn, ":"))
	if err != nil {
		return err
	}
	policy := obj.(*types.NetworkPolicy)
	refs, err := policy.GetVirtualNetworkBackRefs()
	if err == nil {
		for _, ref := range refs {
			netObj, err := m.client.FindByUuid("virtual-network", ref.Uuid)
			if err != nil {
				glog.Errorf("Get network %s: %v", strings.Join(ref.To, ":"), err)
				continue
			}
			m.detachPolicy(netObj.(*types.VirtualNetwork), strings.Join(policy.GetFQName(), ":"))
		}
	}

	// Delete policy
	err = m.client.DeleteByUuid("network-policy", policy.GetUuid())
	return err
}
