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
	"sort"
	"strings"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

type ConsistencyChecker interface {
	Check() bool
}

type policySet map[string]bool
type networkConnectionMap map[string]policySet
type networkServiceMap map[string]ServiceIdList

type consistencyChecker struct {
	client             contrail.ApiClient
	config             *Config
	podStore           cache.StoreToPodLister
	serviceStore       cache.StoreToServiceLister
	networkMgr         NetworkManager
	serviceMgr         ServiceManager
	staleConnectionMap networkConnectionMap
}

func NewConsistencyChecker(client contrail.ApiClient, config *Config, podStore cache.Indexer,
	serviceStore cache.Store, networkMgr NetworkManager, serviceMgr ServiceManager) ConsistencyChecker {
	checker := new(consistencyChecker)
	checker.client = client
	checker.config = config
	checker.podStore = cache.StoreToPodLister{Indexer: podStore}
	checker.serviceStore = cache.StoreToServiceLister{Store: serviceStore}
	checker.networkMgr = networkMgr
	checker.serviceMgr = serviceMgr
	checker.staleConnectionMap = make(networkConnectionMap, 0)
	return checker
}

type deltaFn func(key string)
type compareFn func(key string) bool

func CompareSortedLists(lhs, rhs []string, addFn, delFn deltaFn, cmpFn compareFn) bool {
	equal := true
	i, j := 0, 0

	for i < len(lhs) && j < len(rhs) {
		if lhs[i] < rhs[j] {
			equal = false
			addFn(lhs[i])
			i++
			continue
		} else if lhs[i] > rhs[j] {
			equal = false
			delFn(rhs[j])
			j++
			continue
		}
		if !cmpFn(lhs[i]) {
			equal = false
		}
		i++
		j++
	}
	for ; i < len(lhs); i++ {
		equal = false
		addFn(lhs[i])
	}
	for ; j < len(rhs); j++ {
		equal = false
		delFn(rhs[j])
	}
	return equal
}

func (c *consistencyChecker) instanceGetPod(key string) (*api.Pod, error) {
	obj, exists, _ := c.podStore.GetByKey(key)
	if !exists {
		return nil, fmt.Errorf("cache get %s: failed", key)
	}
	pod, ok := obj.(*api.Pod)
	if !ok {
		return nil, fmt.Errorf("Pod store object: invalid cast")
	}
	return pod, nil
}

func (c *consistencyChecker) vmCompare(pod *api.Pod, instanceId string) bool {
	if string(pod.UID) != instanceId {
		glog.Errorf("pod %s: cache UID %s, virtual-machine %s", pod.Name, string(pod.UID), instanceId)
		return false
	}
	_, err := types.VirtualMachineByUuid(c.client, instanceId)
	if err != nil {
		return false
	}

	return true
}

func (c *consistencyChecker) vmiCompare(pod *api.Pod, interfaceId string) bool {
	vmi, err := types.VirtualMachineInterfaceByUuid(c.client, interfaceId)
	if err != nil {
		return false
	}

	var serviceIpNames sort.StringSlice
	refs, err := vmi.GetFloatingIpBackRefs()
	if err == nil {
		serviceIpMap := make(map[string]bool)
		for _, ref := range refs {
			name := strings.Join(ref.To, ":")
			if _, ok := serviceIpMap[name]; !ok {
				serviceIpMap[name] = true
				serviceIpNames = append(serviceIpNames, name)
			}
		}
	}
	serviceIpNames.Sort()

	var serviceCacheNames sort.StringSlice
	services, err := c.serviceStore.GetPodServices(pod)
	if err == nil {
		for _, service := range services {
			serviceName := ServiceName(c.config, service.Labels)
			serviceNet := fmt.Sprintf(ServiceNetworkFmt, serviceName)
			fqn := []string{c.config.DefaultDomain, service.Namespace, serviceNet, serviceNet, service.Name}
			if service.Spec.ClusterIP != "" {
				serviceCacheNames = append(serviceCacheNames, strings.Join(fqn, ":"))
			}
			if service.Spec.Type == api.ServiceTypeLoadBalancer || len(service.Spec.ExternalIPs) > 0 {
				publicFQN := strings.Split(c.config.PublicNetwork, ":")
				id := fmt.Sprintf("%s:%s:%s_%s",
					c.config.PublicNetwork, publicFQN[len(publicFQN)-1], service.Namespace, service.Name)
				serviceCacheNames = append(serviceCacheNames, id)
			}
		}
	}
	serviceCacheNames.Sort()

	result := CompareSortedLists(
		serviceCacheNames,
		serviceIpNames,
		func(key string) {
			glog.Errorf("interface %s: missing floating-ip for %s", vmi.GetName(), key)
		},
		func(key string) {
			glog.Errorf("interface %s: invalid floating-ip %s", vmi.GetName(), key)
		},
		func(key string) bool {
			return true
		},
	)
	return result
}

func filterPods(store cache.StoreToPodLister, podList []string) []string {
	filteredList := make([]string, 0, len(podList))
	for _, key := range podList {
		item, exists, err := store.GetByKey(key)
		if err != nil || !exists {
			continue
		}
		pod := item.(*api.Pod)
		if IgnorePod(pod) {
			continue
		}
		filteredList = append(filteredList, pod.Name)
	}

	return filteredList
}

func (c *consistencyChecker) collectNetworkServices(pod *api.Pod, connections networkServiceMap) {
	name := getPodNetworkName(pod, c.config)
	fqn := []string{c.config.DefaultDomain, pod.Namespace, name}
	network := strings.Join(fqn, ":")
	serviceList, ok := connections[network]
	if !ok {
		serviceList = MakeServiceIdList()
	}
	buildPodServiceList(pod, c.config, &serviceList)
	connections[network] = serviceList
}

func (c *consistencyChecker) InstanceChecker(connections networkServiceMap) bool {
	podMap := make(map[string]*api.Pod)
	var cacheKeys sort.StringSlice
	cacheKeys = filterPods(c.podStore, c.podStore.ListKeys())
	cacheKeys.Sort()

	elements, err := c.client.List("virtual-machine")
	if err != nil {
		glog.Errorf("%v", err)
		return false
	}
	var instanceKeys sort.StringSlice
	instanceIdMap := make(map[string]string)
	for _, ref := range elements {
		key := fmt.Sprintf("%s", ref.Fq_name[0])
		instanceKeys = append(instanceKeys, key)
		instanceIdMap[key] = ref.Uuid
	}
	instanceKeys.Sort()
	vmCmp := CompareSortedLists(cacheKeys, instanceKeys,
		func(key string) {
			pod, err := c.instanceGetPod(key)
			if err != nil {
				glog.Errorf("%v", err)
			} else {
				podMap[key] = pod
			}
			glog.Errorf("pod %s (UID: %s): instance not present in opencontrail api", key, string(pod.UID))
		},
		func(key string) {
			glog.Errorf("virtual-machine %s (%s): not in local cache", key, instanceIdMap[key])
		},
		func(key string) bool {
			pod, err := c.instanceGetPod(key)
			if err != nil {
				glog.Errorf("%v", err)
				return false
			}
			podMap[key] = pod
			return c.vmCompare(pod, instanceIdMap[key])
		},
	)

	elements, err = c.client.List("virtual-machine-interface")
	if err != nil {
		glog.Errorf("%v", err)
		return false
	}

	var interfaceKeys sort.StringSlice
	interfaceIdMap := make(map[string]string)
	for _, ref := range elements {
		key := fmt.Sprintf("%s", ref.Fq_name[len(ref.Fq_name)-1])
		interfaceKeys = append(interfaceKeys, key)
		interfaceIdMap[key] = ref.Uuid
	}
	interfaceKeys.Sort()

	interfaceCmp := CompareSortedLists(cacheKeys, interfaceKeys,
		func(key string) {
			glog.Errorf("pod %s: interface not present in opencontrail api", key)
		},
		func(key string) {
			glog.Errorf("virtual-machine-interface %s (%s): not in local cache", key, interfaceIdMap[key])
		},
		func(key string) bool {
			pod, ok := podMap[key]
			if !ok {
				var err error
				pod, err = c.instanceGetPod(key)
				if err != nil {
					glog.Errorf("%v", err)
					return false
				}
			}
			return c.vmiCompare(pod, interfaceIdMap[key])
		},
	)

	for _, pod := range podMap {
		c.collectNetworkServices(pod, connections)
	}

	return vmCmp && interfaceCmp
}

// addServiceNetworks is used by NetworkChecker to add all the service network names
// known to kubernetes so these can be compared against the contents present in the
// contrail DB.
func (c *consistencyChecker) addServiceNetworks(kubeNetworks *sort.StringSlice) {
	serviceNetworkMap := make(map[string]bool)
	serviceList, err := c.serviceStore.List()
	if err != nil {
		glog.Error(err)
		return
	}
	for _, svc := range serviceList.Items {
		fqn := []string{c.config.DefaultDomain, svc.Namespace, fmt.Sprintf(ServiceNetworkFmt, ServiceName(c.config, svc.Labels))}
		networkName := strings.Join(fqn, ":")
		if _, ok := serviceNetworkMap[networkName]; !ok {
			serviceNetworkMap[networkName] = true
			*kubeNetworks = append(*kubeNetworks, networkName)
		}
	}
}

var defaultNetworks = []string{
	AddressAllocationNetwork,
	"default-domain:default-project:__link_local__",
	"default-domain:default-project:default-virtual-network",
	"default-domain:default-project:ip-fabric",
}

func isSystemDefaultNetwork(network string) bool {
	for _, name := range defaultNetworks {
		if name == network {
			return true
		}
	}
	return false
}

// connectionShouldDelete returns true when a connection should be deleted.
// When a connection is first considered to be stale it is added to a GC list; if it is considered to be stale
// in two consistency runs, it is deleted.
func (c *consistencyChecker) connectionShouldDelete(network *types.VirtualNetwork, lastIterationMap networkConnectionMap, policyName []string) bool {
	networkName := strings.Join(network.GetFQName(), ":")
	policyCSN := strings.Join(policyName, ":")
	if entry, ok := lastIterationMap[networkName]; ok {
		if _, exists := entry[policyCSN]; exists {
			glog.Infof("%s network connection %s delete", networkName, policyCSN)
			return true
		}
	}

	gcPolicies, exists := c.staleConnectionMap[networkName]
	if !exists {
		gcPolicies = make(policySet, 0)
		c.staleConnectionMap[networkName] = gcPolicies
	}
	glog.Infof("%s network connection %s not used by pod specifications", networkName, policyCSN)
	gcPolicies[policyCSN] = true
	return false
}

func (c *consistencyChecker) networkEvalPolicyRefs(network *types.VirtualNetwork, services ServiceIdList, lastIterationMap networkConnectionMap) (bool, error) {
	policyRefs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		return false, err
	}
	consistent := true
	serviceDeleteList := make([]string, 0)
	gblNetworkDeleteList := make(map[string]string, 0)
	networkCSN := strings.Join(network.GetFQName(), ":")
	for _, ref := range policyRefs {
		if len(ref.To) < 3 {
			glog.Errorf("unexpected policy id %+v", ref.To)
			continue
		}

		if serviceName, err := serviceNameFromPolicyName(ref.To[len(ref.To)-1]); err == nil {
			namespace := ref.To[1]
			if !services.Contains(namespace, serviceName) {
				consistent = false
				if lastIterationMap == nil || c.connectionShouldDelete(network, lastIterationMap, ref.To) {
					serviceDeleteList = append(serviceDeleteList, ref.Uuid)
				}
			}
		} else if targetName, err := globalNetworkFromPolicyName(c.config, ref.To); err == nil {
			if targetName == networkCSN {
				continue
			}
			if !networkAccessGlobalNetworks(c.config, network.GetFQName()) ||
				!isGlobalNetworkName(c.config, targetName) {
				consistent = false
				if lastIterationMap == nil || c.connectionShouldDelete(network, lastIterationMap, ref.To) {
					glog.Infof("Delete connection %s %s", networkCSN, targetName)
					gblNetworkDeleteList[ref.Uuid] = targetName
				} else {
					glog.Infof("Network connection %s %s not used by global network configuration", networkCSN, targetName)
				}
			}
		}
	}

	if len(gblNetworkDeleteList) > 0 {
		c.networkMgr.DeleteConnections(network, gblNetworkDeleteList)
	}

	if len(serviceDeleteList) > 0 {
		c.serviceMgr.DeleteConnections(network, serviceDeleteList)
	}
	return consistent, nil
}

func (c *consistencyChecker) NetworkChecker(connections networkServiceMap) bool {
	lastPolicyMap := c.staleConnectionMap
	c.staleConnectionMap = make(networkConnectionMap, 0)

	var kubeNetworks sort.StringSlice
	connectionCheck := true

	for k, v := range connections {
		kubeNetworks = append(kubeNetworks, k)
		if c.serviceMgr == nil {
			continue
		}
		network, err := types.VirtualNetworkByName(c.client, k)
		if err != nil {
			glog.Error(err)
			continue
		}

		status, err := c.networkEvalPolicyRefs(network, v, lastPolicyMap)
		if err != nil {
			glog.Error(err)
			continue
		}
		if !status {
			connectionCheck = false
		}
	}

	// consider service networks.
	c.addServiceNetworks(&kubeNetworks)

	kubeNetworks.Sort()

	var dbNetworks sort.StringSlice
	elements, err := c.client.List("virtual-network")
	if err != nil {
		glog.Error(err)
		return false
	}
	for _, ref := range elements {
		networkName := strings.Join(ref.Fq_name, ":")
		if networkName == c.config.PublicNetwork {
			continue
		}
		if isSystemDefaultNetwork(networkName) {
			continue
		}
		dbNetworks = append(dbNetworks, networkName)
	}
	dbNetworks.Sort()

	cmp := CompareSortedLists(kubeNetworks, dbNetworks,
		func(key string) {
			glog.Errorf("network %s not present in opencontrail db", key)
		},
		func(key string) {
			glog.Errorf("network %s not used by kubernetes", key)
			if c.serviceMgr == nil {
				return
			}
			network, err := types.VirtualNetworkByName(c.client, key)
			if err != nil {
				glog.Error(err)
				return
			}
			c.networkEvalPolicyRefs(network, MakeServiceIdList(), nil)
		},
		func(key string) bool {
			return true
		})
	return connectionCheck && cmp
}

func (c *consistencyChecker) globalNetworkCheckPolicyAttachment(network *types.VirtualNetwork) bool {
	policyName := makeGlobalNetworkPolicyName(c.config, network.GetFQName())
	policy, err := types.NetworkPolicyByName(c.client, strings.Join(policyName, ":"))
	if err != nil {
		glog.V(3).Infof("No network policy for %s", network.GetName())
		return true
	}
	policyRefs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		glog.Error(err)
		return true
	}

	for _, ref := range policyRefs {
		if ref.Uuid == policy.GetUuid() {
			glog.V(5).Infof("Network %s attached to %s", network.GetName(), policy.GetUuid())
			return true
		}
	}

	err = policyAttach(c.client, network, policy)
	if err != nil {
		glog.Error(err)
	} else {
		glog.Infof("attached global network %s to policy", strings.Join(network.GetFQName(), ":"))
	}
	return false
}

// global networks can be created externally. Attached the network to the respective policy in case
// the policy was created first.
func (c *consistencyChecker) globalNetworkChecker() bool {
	success := true
	for _, gbl := range c.config.GlobalNetworks {
		network, err := types.VirtualNetworkByName(c.client, gbl)
		if err != nil {
			glog.V(5).Infof("Network %s: %v", gbl, err)
			continue
		}
		if !c.globalNetworkCheckPolicyAttachment(network) {
			success = false
		}
	}
	return success
}

func (c *consistencyChecker) Check() bool {
	glog.V(3).Infof("Running consistency checker")
	connections := make(networkServiceMap, 0)
	success := true
	if !c.InstanceChecker(connections) {
		glog.V(3).Infof("instance consistency check failed")
		success = false
	}
	if !c.NetworkChecker(connections) {
		glog.V(3).Infof("network consistency check failed")
		success = false
	}
	if !c.globalNetworkChecker() {
		glog.V(3).Infof("global network consistency check failed")
		success = false
	}
	return success
}
