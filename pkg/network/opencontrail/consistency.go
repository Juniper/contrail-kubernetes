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

type networkConnectionMap map[string]ServiceIdList

type consistencyChecker struct {
	client       contrail.ApiClient
	config       *Config
	podStore     cache.StoreToPodLister
	serviceStore cache.StoreToServiceLister
	serviceMgr   ServiceManager
	gcPolicyMap  networkConnectionMap
}

func NewConsistencyChecker(client contrail.ApiClient, config *Config, podStore cache.Store,
	serviceStore cache.Store, serviceMgr ServiceManager) ConsistencyChecker {
	checker := new(consistencyChecker)
	checker.client = client
	checker.config = config
	checker.podStore = cache.StoreToPodLister{podStore}
	checker.serviceStore = cache.StoreToServiceLister{serviceStore}
	checker.serviceMgr = serviceMgr
	checker.gcPolicyMap = make(networkConnectionMap, 0)
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
		filteredList = append(filteredList, key)
	}

	return filteredList
}

func (c *consistencyChecker) collectNetworkConnections(pod *api.Pod, connections networkConnectionMap) {
	name := PodNetworkName(pod, c.config)
	fqn := []string{c.config.DefaultDomain, pod.Namespace, name}
	network := strings.Join(fqn, ":")
	serviceList, ok := connections[network]
	if !ok {
		serviceList = MakeServiceIdList()
		for _, svc := range c.config.ClusterServices {
			namespace, service := serviceIdFromName(svc)
			serviceList.Add(namespace, service)
		}
	}
	BuildPodServiceList(pod, c.config, &serviceList)
	connections[network] = serviceList
}

func (c *consistencyChecker) InstanceChecker(connections networkConnectionMap) bool {
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
		key := fmt.Sprintf("%s/%s", ref.Fq_name[len(ref.Fq_name)-2], ref.Fq_name[len(ref.Fq_name)-1])
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
		key := fmt.Sprintf("%s/%s", ref.Fq_name[len(ref.Fq_name)-2], ref.Fq_name[len(ref.Fq_name)-1])
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
		c.collectNetworkConnections(pod, connections)
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

func (c *consistencyChecker) NetworkChecker(connections networkConnectionMap) bool {
	lastPolicyMap := c.gcPolicyMap
	c.gcPolicyMap = make(networkConnectionMap, 0)

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

		// State policy references are removed if they are found to be stale in
		// two successive cycles.
		c.serviceMgr.PurgeStalePolicyRefs(network, v,
			func(namespace, service string) bool {
				networkName := strings.Join(network.GetFQName(), ":")
				if entry, ok := lastPolicyMap[networkName]; ok {
					if entry.Contains(namespace, service) {
						glog.Infof("%s service connection %s/%s delete", networkName, namespace, service)
						connectionCheck = false
						return true
					}
				}
				var serviceList ServiceIdList
				if entry, ok := c.gcPolicyMap[networkName]; ok {
					serviceList = entry
				} else {
					serviceList = MakeServiceIdList()
				}
				glog.Infof("%s service connection %s/%s not used by pod specifications",
					networkName, namespace, service)
				serviceList.Add(namespace, service)
				c.gcPolicyMap[networkName] = serviceList
				connectionCheck = false
				return false
			})
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
			c.serviceMgr.PurgeStalePolicyRefs(network, MakeServiceIdList(), func(string, string) bool { return true })
		},
		func(key string) bool {
			return true
		})
	return connectionCheck && cmp
}

func (c *consistencyChecker) Check() bool {
	glog.V(3).Infof("Running consistency checker")
	connections := make(networkConnectionMap, 0)
	success := true
	if !c.InstanceChecker(connections) {
		success = false
	}
	if !c.NetworkChecker(connections) {
		success = false
	}
	return success
}
