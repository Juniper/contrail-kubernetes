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

// ServiceManager defines the interface between the Controller and the class that manages
// the contrail API representation of Services
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

type serviceManagerImpl struct {
	client     contrail.ApiClient
	config     *Config
	networkMgr NetworkManager
}

const (
	serviceNetworkFmt = "service-%s"
)

// NewServiceManager allocates and initializes a ServiceManager implementation.
func NewServiceManager(client contrail.ApiClient, config *Config, networkMgr NetworkManager) ServiceManager {
	serviceMgr := new(serviceManagerImpl)
	serviceMgr.client = client
	serviceMgr.config = config
	serviceMgr.networkMgr = networkMgr
	return serviceMgr
}

func (m *serviceManagerImpl) LocateServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error) {
	networkName := fmt.Sprintf(serviceNetworkFmt, serviceName)
	network, err := m.networkMgr.LocateNetwork(tenant, networkName, m.config.ServiceSubnet)
	if err != nil {
		return nil, err
	}
	m.networkMgr.LocateFloatingIPPool(network)
	return network, nil
}

func (m *serviceManagerImpl) LookupServiceNetwork(tenant, serviceName string) (*types.VirtualNetwork, error) {
	networkName := fmt.Sprintf(serviceNetworkFmt, serviceName)
	return m.networkMgr.LookupNetwork(tenant, networkName)
}

func (m *serviceManagerImpl) IsEmpty(tenant, serviceName string) (bool, []string) {
	empty := []string{}
	network, err := m.LookupServiceNetwork(tenant, serviceName)
	if err != nil {
		return true, empty
	}
	pool, err := m.networkMgr.LookupFloatingIPPool(network)
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
	for key := range existMap {
		existing = append(existing, key)
	}
	return false, existing
}

func makeServicePolicyName(config *Config, tenant, serviceName string) []string {
	return []string{config.DefaultDomain, tenant, servicePolicyPrefix + serviceName}
}

func serviceNameFromPolicyName(policyName string) (string, error) {
	if strings.HasPrefix(policyName, servicePolicyPrefix) {
		return policyName[len(servicePolicyPrefix):], nil
	}
	return "", fmt.Errorf("%s is not a service policy", policyName)
}

func (m *serviceManagerImpl) locatePolicy(tenant, serviceName string) (*types.NetworkPolicy, error) {
	var policy *types.NetworkPolicy

	policyName := makeServicePolicyName(m.config, tenant, serviceName)
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
func (m *serviceManagerImpl) Connect(tenant, serviceName string, network *types.VirtualNetwork) error {
	policy, err := m.locatePolicy(tenant, serviceName)
	if err != nil {
		return err
	}
	policyAttach(m.client, network, policy)
	serviceNet, err := m.LookupServiceNetwork(tenant, serviceName)
	if err == nil {
		policyLocateRule(m.client, policy, network, serviceNet)
	}
	return nil
}

func (m *serviceManagerImpl) Create(tenant, serviceName string) error {
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
			policyLocateRule(m.client, policy, lhs, network)
		}
	}
	policyAttach(m.client, network, policy)
	return nil
}

func (m *serviceManagerImpl) Delete(tenant, serviceName string) error {
	policyName := makeServicePolicyName(m.config, tenant, serviceName)

	// Delete network
	networkName := fmt.Sprintf(serviceNetworkFmt, serviceName)
	network, err := m.networkMgr.LookupNetwork(tenant, networkName)
	if network != nil {
		policyDetach(m.client, network, strings.Join(policyName, ":"))
		m.networkMgr.DeleteFloatingIPPool(network, true)

		// Do not delete cluster-service networks.
		// Often the cluster-service network is statically configured on a
		// software gateway. When that is the case, the delete is not processed
		// by the control-node since the downstream compute-node is still subscribed
		// to the corresponding routing-instance.
		if !isClusterService(m.config, tenant, serviceName) {
			m.networkMgr.DeleteNetwork(network)
		}
	}

	policy, err := m.releasePolicyIfEmpty(tenant, serviceName)
	if policy != nil {
		// flush all policy rules
		policy.SetNetworkPolicyEntries(&types.PolicyEntriesType{})
		err = m.client.Update(policy)
	}
	return err
}

func (m *serviceManagerImpl) releasePolicyIfEmpty(tenant, serviceName string) (*types.NetworkPolicy, error) {
	policyName := makeServicePolicyName(m.config, tenant, serviceName)
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

func (m *serviceManagerImpl) Disconnect(tenant, serviceName, netName string) error {
	policy, err := m.releasePolicyIfEmpty(tenant, serviceName)
	if policy != nil {
		netFQN := []string{m.config.DefaultDomain, tenant, netName}
		serviceFQN := []string{m.config.DefaultDomain, tenant, fmt.Sprintf(serviceNetworkFmt, serviceName)}
		err = policyDeleteRule(m.client, policy, strings.Join(netFQN, ":"), strings.Join(serviceFQN, ":"))
		return err
	}
	return nil
}

func (m *serviceManagerImpl) DeleteConnections(network *types.VirtualNetwork, purgeList []string) error {
	if len(purgeList) == 0 {
		return nil
	}
	for _, policyID := range purgeList {
		network.DeleteNetworkPolicy(policyID)
	}
	err := m.client.Update(network)
	if err != nil {
		return err
	}
	for _, policyID := range purgeList {
		policy, err := types.NetworkPolicyByUuid(m.client, policyID)
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
