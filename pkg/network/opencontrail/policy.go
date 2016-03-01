/*
Copyright 2016 Juniper Networks, Inc. All rights reserved.

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

func policyLocateRule(client contrail.ApiClient, policy *types.NetworkPolicy, lhs, rhs *types.VirtualNetwork) error {
	return policyLocateRuleByFQN(client, policy, lhs.GetFQName(), rhs.GetFQName())
}

func policyLocateRuleByFQN(client contrail.ApiClient, policy *types.NetworkPolicy, lhsFQN, rhsFQN []string) error {
	lhsName := strings.Join(lhsFQN, ":")
	rhsName := strings.Join(rhsFQN, ":")
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
	rule.SrcPorts = []types.PortType{types.PortType{StartPort: -1, EndPort: -1}}
	rule.DstPorts = []types.PortType{types.PortType{StartPort: -1, EndPort: -1}}
	rule.ActionList = &types.ActionListType{
		SimpleAction: "pass",
	}

	entries.AddPolicyRule(rule)
	policy.SetNetworkPolicyEntries(&entries)
	err := client.Update(policy)
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

func policyDeleteRule(client contrail.ApiClient, policy *types.NetworkPolicy, lhsName, rhsName string) error {
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
	err := client.Update(policy)
	if err != nil {
		glog.Errorf("policy-rule: %v", err)
	}
	return err
}

func policyAttach(client contrail.ApiClient, network *types.VirtualNetwork, policy *types.NetworkPolicy) error {
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
			Sequence: &types.SequenceType{Major: 10, Minor: 0},
		})
	err = client.Update(network)
	if err != nil {
		glog.Errorf("Update network %s policies: %v", network.GetName(), err)
		return err
	}
	return nil
}

func policyDetach(client contrail.ApiClient, network *types.VirtualNetwork, policyName string) error {
	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		glog.Errorf("get network policy-refs %s: %v", network.GetName(), err)
		return err
	}
	for _, ref := range refs {
		if strings.Join(ref.To, ":") == policyName {
			network.DeleteNetworkPolicy(ref.Uuid)
			err := client.Update(network)
			if err != nil {
				glog.Errorf("Update network %s policies: %v", network.GetName(), err)
			}
			return err
		}
	}
	return nil
}
