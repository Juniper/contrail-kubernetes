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

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/unversioned/cache"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

type ConsistencyChecker interface {
	Check() bool
}

type consistencyChecker struct {
	client       contrail.ApiClient
	podStore     cache.StoreToPodLister
	serviceStore cache.StoreToServiceLister
}

func NewConsistencyChecker(client contrail.ApiClient, podStore cache.Store, serviceStore cache.Store) ConsistencyChecker {
	checker := new(consistencyChecker)
	checker.client = client
	checker.podStore = cache.StoreToPodLister{podStore}
	checker.serviceStore = cache.StoreToServiceLister{serviceStore}
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
			name := ref.To[len(ref.To)-1]
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
			serviceCacheNames = append(serviceCacheNames, service.Name)
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

func (c *consistencyChecker) InstanceChecker() bool {
	podMap := make(map[string]*api.Pod)
	var cacheKeys sort.StringSlice
	cacheKeys = c.podStore.ListKeys()
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
	return vmCmp && interfaceCmp
}

func (c *consistencyChecker) Check() bool {
	if !c.InstanceChecker() {
		return false
	}
	return true
}
