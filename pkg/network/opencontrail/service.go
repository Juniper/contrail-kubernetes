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
	DeleteConnections(*types.VirtualNetwork, []string) error
}

type ServiceManagerImpl struct {
	client     contrail.ApiClient
	config     *Config
	networkMgr NetworkManager
}

const (
	ServiceNetworkFmt = "service-%s"
)

func getServiceProjectName() string {
	// here we will return a different namespace depending on the isolation mode
	return DefaultServiceProjectName
}

func getServiceNetworkName() string {
	// here we will return a different namespace depending on the isolation mode
	return DefaultServiceNetworkName
}

func NewServiceManager(client contrail.ApiClient, config *Config, networkMgr NetworkManager) ServiceManager {
	serviceMgr := new(ServiceManagerImpl)
	serviceMgr.client = client
	serviceMgr.config = config
	serviceMgr.networkMgr = networkMgr
	return serviceMgr
}

func (m *ServiceManagerImpl) LocateServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error) {
	var project = getServiceProjectName()
	var networkName = getServiceNetworkName()
	network, err := m.networkMgr.LocateNetwork(project, networkName, m.config.ServiceSubnet)
	if err != nil {
		return nil, err
	}
	m.networkMgr.LocateFloatingIpPool(network)
	return network, nil
}

func (m *ServiceManagerImpl) LookupServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error) {
	var project = getServiceProjectName()
	var networkName = getServiceNetworkName()
	return m.networkMgr.LookupNetwork(project, networkName)
}

func (m *ServiceManagerImpl) IsEmpty(tenant, serviceName string) (bool, []string) {
	empty := []string{}
	var project = getServiceProjectName()
	network, err := m.LookupServiceNetwork(project, serviceName)
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

func makeServicePolicyName(config *Config, tenant, serviceName string) []string {
	var project = getServiceProjectName()
	return []string{config.DefaultDomain, project, servicePolicyPrefix + serviceName}
}

func serviceNameFromPolicyName(policyName string) (string, error) {
	if strings.HasPrefix(policyName, servicePolicyPrefix) {
		return policyName[len(servicePolicyPrefix):], nil
	}
	return "", fmt.Errorf("%s is not a service policy", policyName)
}

func (m *ServiceManagerImpl) locatePolicy(tenant, serviceName string) (*types.NetworkPolicy, error) {
	var policy *types.NetworkPolicy = nil
	var project = getServiceProjectName()
	policyName := makeServicePolicyName(m.config, project, serviceName)
	obj, err := m.client.FindByName("network-policy", strings.Join(policyName, ":"))
	if err != nil {
		policy = new(types.NetworkPolicy)
		policy.SetFQName("project", policyName)
		err = m.client.Create(policy)
		if err != nil {
			glog.Errorf("Create policy %s: %v", strings.Join(policyName, ":"), err)
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
	var project = getServiceProjectName();
	policy, err := m.locatePolicy(project, serviceName)
	if err != nil {
		return err
	}
	policyAttach(m.client, network, policy)
	serviceNet, err := m.LookupServiceNetwork(project, serviceName)
	if err == nil {
		policyLocateRule(m.client, policy, network, serviceNet)
	}
	return nil
}

func (m *ServiceManagerImpl) Create(tenant, serviceName string) error {
	var project = getServiceProjectName();
	network, err := m.LocateServiceNetwork(project, serviceName)
	if err != nil {
		return err
	}
	policy, err := m.locatePolicy(project, serviceName)
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
			policyLocateRule(m.client, policy, lhs, network)
		}
	}
	policyAttach(m.client, network, policy)
	return nil
}

func (m *ServiceManagerImpl) Delete(tenant, serviceName string) error {
	var project = getServiceProjectName();
	policyName := makeServicePolicyName(m.config, project, serviceName)

	// Delete network
	var networkName = getServiceNetworkName();
	network, err := m.networkMgr.LookupNetwork(project, networkName)
	if network != nil {
		policyDetach(m.client, network, strings.Join(policyName, ":"))
		m.networkMgr.DeleteFloatingIpPool(network, true)

		// Do not delete cluster-service networks.
		// Often the cluster-service network is statically configured on a
		// software gateway. When that is the case, the delete is not processed
		// by the control-node since the downstream compute-node is still subscribed
		// to the corresponding routing-instance.
		if !IsClusterService(m.config, project, serviceName) {
			m.networkMgr.DeleteNetwork(network)
		}
	}

	policy, err := m.releasePolicyIfEmpty(project, serviceName)
	if policy != nil {
		// flush all policy rules
		policy.SetNetworkPolicyEntries(&types.PolicyEntriesType{})
		err = m.client.Update(policy)
	}
	return err
}

func (m *ServiceManagerImpl) releasePolicyIfEmpty(tenant, serviceName string) (*types.NetworkPolicy, error) {
	var project = getServiceProjectName();
	policyName := makeServicePolicyName(m.config, project, serviceName)
	policy, err := types.NetworkPolicyByName(m.client, strings.Join(policyName, ":"))
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
	var project = getServiceProjectName();
	policy, err := m.releasePolicyIfEmpty(project, serviceName)
	if policy != nil {
		netFQN := []string{m.config.DefaultDomain, project, netName}
		serviceFQN := []string{m.config.DefaultDomain, project, fmt.Sprintf(ServiceNetworkFmt, serviceName)}
		err = policyDeleteRule(m.client, policy, strings.Join(netFQN, ":"), strings.Join(serviceFQN, ":"))
		return err
	}
	return nil
}

func (m *ServiceManagerImpl) DeleteConnections(network *types.VirtualNetwork, purgeList []string) error {
	if len(purgeList) == 0 {
		return nil
	}
	for _, policyId := range purgeList {
		network.DeleteNetworkPolicy(policyId)
	}
	err := m.client.Update(network)
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
			continue
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
