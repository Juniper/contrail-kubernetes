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

	kubeclient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/api"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

type ServiceManager interface {
	Create(service *api.Service) error
	Delete(service *api.Service) error
	GetServiceNetwork(service *api.Service) (*types.VirtualNetwork)
	GetServiceName(service *api.Service) string
    ConnectNetworks(podNetwork, serviceNetwork *types.VirtualNetwork) error
	Connect(network *types.VirtualNetwork, tenant, serviceName string) error
	Disconnect(podNetwork *types.VirtualNetwork, project, serviceName string) error
	DeleteConnections(*types.VirtualNetwork, []string) error
}

type ServiceManagerImpl struct {
	client     contrail.ApiClient
	config     *Config
	networkMgr NetworkManager
	kube kubeclient.Interface
}

const (
	ServiceNetworkFmt = "service-%s"
)

func NewServiceManager(client contrail.ApiClient, config *Config, networkMgr NetworkManager,
		kube kubeclient.Interface) ServiceManager {

	serviceMgr := new(ServiceManagerImpl)
	serviceMgr.client = client
	serviceMgr.config = config
	serviceMgr.networkMgr = networkMgr
	serviceMgr.kube = kube
	return serviceMgr
}

func (m *ServiceManagerImpl) GetServiceName(service *api.Service) string {
	name, ok := service.Labels[m.config.NetworkTag]
	if !ok {
		return ClusterNetworkName
	}

	return name
}

func (m *ServiceManagerImpl) GetServiceNetwork(service *api.Service) (*types.VirtualNetwork) {
	// returned network will depend on the namespace isolation mode
	// for now only cluster-network is supported
	return m.networkMgr.GetClusterNetwork()
}

func (m *ServiceManagerImpl) IsEmpty(service *api.Service) (bool, []string) {
	empty := []string{}
	network :=  m.GetServiceNetwork(service)
	if network == nil {
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

func makeServicePolicyName(config *Config, serviceNetwork *types.VirtualNetwork) []string {
	project := serviceNetwork.GetFQName()[1]
	return []string{config.DefaultDomain, project, servicePolicyPrefix + serviceNetwork.GetName()}
}

func serviceNameFromPolicyName(policyName string) (string, error) {
	if strings.HasPrefix(policyName, servicePolicyPrefix) {
		return policyName[len(servicePolicyPrefix):], nil
	}
	return "", fmt.Errorf("%s is not a service policy", policyName)
}

func (m *ServiceManagerImpl) ConnectNetworks(podNetwork, serviceNetwork *types.VirtualNetwork) error {
	policyName := makeServicePolicyName(m.config, serviceNetwork)
	policy, err := locatePolicy(m.client, policyName)
	if err != nil {
		return err
	}
	policyAttach(m.client, podNetwork, policy)

	policyLocateRule(m.client, policy, podNetwork, serviceNetwork)

	return nil
}

// Attach the network to the service policy.
// The policy can be created either by the first referer or when the service is created.
func (m *ServiceManagerImpl) Connect(podNetwork *types.VirtualNetwork, project, serviceName string) error {

	svc, err := m.kube.Services(project).Get(serviceName)
	if err != nil {
		glog.Warningf("Error retrievng service %s/%s: %s", project, serviceName, err)
		return err
	}
	return m.ConnectNetworks(podNetwork, m.GetServiceNetwork(svc))
}

func (m *ServiceManagerImpl) Create(service *api.Service) error {
	serviceNetwork := m.GetServiceNetwork(service)
	policyName := makeServicePolicyName(m.config, serviceNetwork)
	policy, err := locatePolicy(m.client, policyName)

	if err != nil {
		return nil
	}

	refs, err := policy.GetVirtualNetworkBackRefs()
	if err == nil {
		for _, ref := range refs {
			if ref.Uuid == serviceNetwork.GetUuid() {
				continue
			}
			lhs, err := types.VirtualNetworkByUuid(m.client, ref.Uuid)
			if err != nil {
				continue
			}
			policyLocateRule(m.client, policy, lhs, serviceNetwork)
		}
	}
	policyAttach(m.client, serviceNetwork, policy)
	return nil
}

func (m *ServiceManagerImpl) Delete(service *api.Service) error {
	serviceName := m.GetServiceName(service)

	serviceNetwork := m.GetServiceNetwork(service)

	empty, remaining := m.IsEmpty(service)
	if !empty {
		for _, name := range remaining {
			_, err := m.kube.Services(service.Namespace).Get(name)
			if err != nil {
				glog.Warningf("Service network %s has floating-ip addresses for service %s (NOT in cache)",
					serviceName, name)
			}
		}
		return nil
	}

	policyName := makeServicePolicyName(m.config, serviceNetwork)


	policyDetach(m.client, serviceNetwork, strings.Join(policyName, ":"))
	m.networkMgr.DeleteFloatingIpPool(serviceNetwork, true)

	// Do not delete cluster-service networks.
	// Often the cluster-service network is statically configured on a
	// software gateway. When that is the case, the delete is not processed
	// by the control-node since the downstream compute-node is still subscribed
	// to the corresponding routing-instance.
	if (serviceNetwork != m.networkMgr.GetClusterNetwork()) && (!IsClusterService(m.config, service.Namespace, serviceName)) {
		m.networkMgr.DeleteNetwork(serviceNetwork)
	}

	policy, err := m.releasePolicyIfEmpty(serviceNetwork)
	if policy != nil {
		// flush all policy rules
		policy.SetNetworkPolicyEntries(&types.PolicyEntriesType{})
		err = m.client.Update(policy)
	}
	return err
}

func (m *ServiceManagerImpl) releasePolicyIfEmpty(network *types.VirtualNetwork) (*types.NetworkPolicy, error) {
	policyName := makeServicePolicyName(m.config, network)
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
		glog.Errorf("Release policy %s: %v", network, err)
	}

	return policy, err
}

func (m *ServiceManagerImpl) Disconnect(podNetwork *types.VirtualNetwork, project, serviceName string) error {
	svc, err := m.kube.Services(project).Get(serviceName)
	if err != nil {
		glog.Warningf("Error retrieving service %s/%s: %s", project, serviceName, err)
		return err
	}
	policy, err := m.releasePolicyIfEmpty(m.GetServiceNetwork(svc))
	if policy != nil {
		netFQN := []string{m.config.DefaultDomain, project, podNetwork.GetName()}
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
