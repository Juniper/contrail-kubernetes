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
	Disconnect(tenant, serviceName, netname string) error
	LocateServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error)
	LookupServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error)
	IsEmpty(tenant, serviceName string) (bool, []string)
	PurgeStalePolicyRefs(*types.VirtualNetwork, ServiceIdList, func(string, string) bool) error
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

func (m *ServiceManagerImpl) locatePolicyRule(policy *types.NetworkPolicy, lhs, rhs *types.VirtualNetwork) error {
	lhsName := strings.Join(lhs.GetFQName(), ":")
	rhsName := strings.Join(rhs.GetFQName(), ":")

	entries := policy.GetNetworkPolicyEntries()
	for _, rule := range entries.PolicyRule {
		if rule.SrcAddresses[0].VirtualNetwork == lhsName &&
			rule.DstAddresses[0].VirtualNetwork == rhsName {
			return nil
		}
	}
	rule := new(types.PolicyRuleType)
	rule.Protocol = "any"
	rule.Direction = "<>"
	rule.SrcAddresses = []types.AddressType{types.AddressType{
		VirtualNetwork: lhsName,
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

func removeRulesIndex(rules []types.PolicyRuleType, index int) []types.PolicyRuleType {
	rules[index], rules = rules[len(rules)-1], rules[:len(rules)-1]
	return rules
}

func (m *ServiceManagerImpl) deletePolicyRule(policy *types.NetworkPolicy, lhsName, rhsName string) error {
	entries := policy.GetNetworkPolicyEntries()
	var index int = -1
	for i, rule := range entries.PolicyRule {
		if rule.SrcAddresses[0].VirtualNetwork == lhsName &&
			rule.DstAddresses[0].VirtualNetwork == rhsName {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	entries.PolicyRule = removeRulesIndex(entries.PolicyRule, index)
	policy.SetNetworkPolicyEntries(&entries)
	err := m.client.Update(policy)
	if err != nil {
		glog.Errorf("policy-rule: %v", err)
	}
	return err
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

func (m *ServiceManagerImpl) LookupServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error) {
	networkName := fmt.Sprintf(ServiceNetworkFmt, serviceName)
	return m.networkMgr.LookupNetwork(tenant, networkName)
}

func (m *ServiceManagerImpl) IsEmpty(tenant, serviceName string) (bool, []string) {
	empty := []string{}
	network, err := m.LookupServiceNetwork(tenant, serviceName)
	if err != nil {
		return true, empty
	}
	pool, err := m.networkMgr.LookupFloatingIpPool(network)
	if err != nil {
		return true, empty
	}
	refs, err := pool.GetFloatingIps()
	if err != nil {
		return true, empty
	}
	existMap := make(map[string]bool)
	for _, ref := range refs {
		name := ref.To[len(ref.To)-1]
		if _, ok := existMap[name]; !ok {
			existMap[name] = true
		}
	}
	if len(existMap) == 0 {
		return true, empty
	}
	existing := make([]string, 0, len(existMap))
	for key, _ := range existMap {
		existing = append(existing, key)
	}
	return false, existing
}

func (m *ServiceManagerImpl) locatePolicy(tenant, serviceName string) (*types.NetworkPolicy, error) {
	var policy *types.NetworkPolicy = nil

	fqn := []string{m.config.DefaultDomain, tenant, serviceName}
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
// The policy can be created either by the first referer or when the service is created.
func (m *ServiceManagerImpl) Connect(tenant, serviceName string, network *types.VirtualNetwork) error {
	policy, err := m.locatePolicy(tenant, serviceName)
	if err != nil {
		return err
	}
	m.attachPolicy(network, policy)
	serviceNet, err := m.LookupServiceNetwork(tenant, serviceName)
	if err == nil {
		m.locatePolicyRule(policy, network, serviceNet)
	}
	return nil
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

	refs, err := policy.GetVirtualNetworkBackRefs()
	if err == nil {
		for _, ref := range refs {
			if ref.Uuid == network.GetUuid() {
				continue
			}
			lhs, err := types.VirtualNetworkByUuid(m.client, ref.Uuid)
			if err != nil {
				continue
			}
			m.locatePolicyRule(policy, lhs, network)
		}
	}
	m.attachPolicy(network, policy)
	return nil
}

func (m *ServiceManagerImpl) Delete(tenant, serviceName string) error {
	fqn := []string{m.config.DefaultDomain, tenant, serviceName}

	// Delete network
	networkName := fmt.Sprintf(ServiceNetworkFmt, serviceName)
	network, err := m.networkMgr.LookupNetwork(tenant, networkName)
	if network != nil {
		m.detachPolicy(network, strings.Join(fqn, ":"))
		m.networkMgr.DeleteFloatingIpPool(network, true)
		m.networkMgr.DeleteNetwork(network)
	}

	policy, err := m.releasePolicyIfEmpty(tenant, serviceName)
	if policy != nil {
		// flush all policy rules
		policy.SetNetworkPolicyEntries(&types.PolicyEntriesType{})
		err = m.client.Update(policy)
	}
	return err
}

func (m *ServiceManagerImpl) releasePolicyIfEmpty(tenant, serviceName string) (*types.NetworkPolicy, error) {
	fqn := []string{m.config.DefaultDomain, tenant, serviceName}
	policy, err := types.NetworkPolicyByName(m.client, strings.Join(fqn, ":"))
	if err != nil {
		return nil, nil
	}
	refs, err := policy.GetVirtualNetworkBackRefs()
	if err == nil && len(refs) == 0 {
		// Delete policy
		err = m.client.Delete(policy)
		if err == nil {
			return nil, nil
		}
	} else if err != nil {
		glog.Errorf("Release policy %s: %v", serviceName, err)
	}

	return policy, err
}

func (m *ServiceManagerImpl) Disconnect(tenant, serviceName, netName string) error {
	policy, err := m.releasePolicyIfEmpty(tenant, serviceName)
	if policy != nil {
		netFQN := []string{m.config.DefaultDomain, tenant, netName}
		serviceFQN := []string{m.config.DefaultDomain, tenant, fmt.Sprintf(ServiceNetworkFmt, serviceName)}
		err = m.deletePolicyRule(policy, strings.Join(netFQN, ":"), strings.Join(serviceFQN, ":"))
		return err
	}
	return nil
}

func (m *ServiceManagerImpl) PurgeStalePolicyRefs(network *types.VirtualNetwork, services ServiceIdList,
	doDelete func(string, string) bool) error {
	purgeList := make([]string, 0)
	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if len(ref.To) < 3 {
			glog.Errorf("unexpected policy id %+v", ref.To)
			continue
		}
		namespace := ref.To[1]
		serviceName := ref.To[len(ref.To)-1]
		if !services.Contains(namespace, serviceName) && doDelete(namespace, serviceName) {
			purgeList = append(purgeList, ref.Uuid)
		}
	}
	if len(purgeList) == 0 {
		return nil
	}
	for _, policyId := range purgeList {
		network.DeleteNetworkPolicy(policyId)
	}
	err = m.client.Update(network)
	if err != nil {
		return err
	}
	for _, policyId := range purgeList {
		policy, err := types.NetworkPolicyByUuid(m.client, policyId)
		if err != nil {
			glog.Error(err)
			continue
		}
		refs, err := policy.GetVirtualNetworkBackRefs()
		if err != nil {
			glog.Error(err)
		}
		if len(refs) == 0 {
			err = m.client.Delete(policy)
			if err != nil {
				glog.Error(err)
			}
		}
	}
	return nil
}
