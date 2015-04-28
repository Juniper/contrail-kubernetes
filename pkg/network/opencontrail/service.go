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
	"strings"

	"github.com/golang/glog"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

type ServiceManager struct {
	client *contrail.Client
}

func NewServiceManager(client *contrail.Client, config *Config) *ServiceManager {
	serviceMan := new(ServiceManager)
	serviceMan.client = client
	return serviceMan
}

func (m *ServiceManager) locatePolicyRule(policy *types.NetworkPolicy, lhs, rhs *types.VirtualNetwork) {
	lhsName := strings.Join(lhs.GetFQName(), ":")
	rhsName := strings.Join(rhs.GetFQName(), ":")

	entries := policy.GetNetworkPolicyEntries()
	for _, rule := range entries.PolicyRule {
		if rule.SrcAddresses[0].VirtualNetwork == lhsName &&
			rule.DstAddresses[0].VirtualNetwork == rhsName {
			return
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
	}
}

func (m *ServiceManager) attachPolicy(network *types.VirtualNetwork, policy *types.NetworkPolicy) {
	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		glog.Errorf("get network policy-refs %s: %v", network.GetName(), err)
		return
	}
	for _, ref := range refs {
		if ref.Uuid == policy.GetUuid() {
			return
		}
	}
	network.AddNetworkPolicy(policy,
		types.VirtualNetworkPolicyType{
			Sequence: &types.SequenceType{10, 0},
		})
	err = m.client.Update(network)
	if err != nil {
		glog.Errorf("Update network %s policies: %v", network.GetName(), err)
	}
}

// create a policy that connects two networks.
func (m *ServiceManager) NetworkAccess(
	network *types.VirtualNetwork, policyName, policyTag string) {
	glog.Infof("policy %s: %s <=> %s", policyName, network.GetName(), policyTag)
	networkFQN := network.GetFQName()
	fqn := AppendConst(networkFQN[0:len(networkFQN)-1], policyName)

	var policy *types.NetworkPolicy = nil
	obj, err := m.client.FindByName("network-policy", strings.Join(fqn, ":"))

	if err != nil {
		policy = new(types.NetworkPolicy)
		policy.SetFQName("project", fqn)
		err = m.client.Create(policy)
		if err != nil {
			glog.Errorf("Create policy %s: %v", policyName, err)
			return
		}
	} else {
		policy = obj.(*types.NetworkPolicy)
	}

	rhsName := AppendConst(networkFQN[0:len(networkFQN)-1], policyTag)
	obj, err = m.client.FindByName("virtual-network", strings.Join(rhsName, ":"))
	if err != nil {
		glog.Errorf("GET virtual-network %s: %v", policyTag, err)
		return
	}
	rhsNetwork := obj.(*types.VirtualNetwork)
	m.locatePolicyRule(policy, network, rhsNetwork)
	m.attachPolicy(network, policy)
	m.attachPolicy(rhsNetwork, policy)
}
