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
	"math/rand"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/stretchr/testify/mock"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/labels"

	"github.com/Juniper/contrail-go-api"
	contrail_mocks "github.com/Juniper/contrail-go-api/mocks"
	"github.com/Juniper/contrail-go-api/types"

	"github.com/Juniper/contrail-kubernetes/pkg/network/opencontrail/mocks"
)

// TestGroupState stores information about a group of pods (managed by an RC)
// and service defintion.
type TestGroupState struct {
	Pods     []*api.Pod
	Services []*api.Service
}

// TestFramework contains the several mock objects required to simulate the kubernetes
// environment. The mocks are updated when objects are added or deleted.
type TestFramework struct {
	client       *contrail_mocks.ApiClient
	kubeMock     *mocks.KubeClient
	podStore     *mocks.Store
	serviceStore *mocks.Store
	controller   *Controller
	config       *Config
	checker      ConsistencyChecker
	state        map[string]*TestGroupState
	clusterIPs   map[int]string
	keyList      []string
	shutdown     chan struct{}
}

func (t *TestFramework) SetUp(publicSubnet string) {
	t.client = new(contrail_mocks.ApiClient)
	t.client.Init()

	t.client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	t.client.AddInterceptor("virtual-network", &NetworkInterceptor{})
	t.client.AddInterceptor("instance-ip", &IpInterceptor{})
	t.client.AddInterceptor("floating-ip", &FloatingIpInterceptor{})

	t.podStore = new(mocks.Store)
	t.serviceStore = new(mocks.Store)

	t.kubeMock = mocks.NewKubeClient()
	t.config = NewConfig()
	t.config.PublicSubnet = publicSubnet
	t.controller = makeSyncController(t.kubeMock, t.config)
	t.controller.SetPodStore(t.podStore)
	t.controller.SetServiceStore(t.serviceStore)
	t.controller.initComponents(t.client)

	t.checker = t.controller.newConsistencyChecker()

	for _, projectName := range testProjects {
		project := new(types.Project)
		project.SetFQName("domain", []string{t.config.DefaultDomain, projectName})
		t.client.Create(project)
	}

	t.state = make(map[string]*TestGroupState, 0)
	t.clusterIPs = make(map[int]string, 0)
	t.keyList = make([]string, 0)

	t.shutdown = make(chan struct{})

	keysCall := t.podStore.On("ListKeys").Return()
	keysCall.Run(func(arg mock.Arguments) {
		keysCall.Return(t.keyList)
	})

	listCall := t.serviceStore.On("List").Return()
	listCall.Run(func(arg mock.Arguments) {
		serviceList := make([]interface{}, 0)
		for _, v := range t.state {
			for _, svc := range v.Services {
				serviceList = append(serviceList, svc)
			}
		}
		listCall.Return(serviceList)
	})
}

func (t *TestFramework) Start() {
	go t.controller.Run(t.shutdown)
}

func (t *TestFramework) Shutdown() {
	type shutdownMsg struct {
	}
	t.shutdown <- shutdownMsg{}
}

func (t *TestFramework) SyncBarrier() {
	t.controller.eventChannel <- notification{event: evSync}
}

func (t *TestFramework) GetGroupState(namespace, name string) *TestGroupState {
	key := namespace + "/" + name
	data, exists := t.state[key]
	if !exists {
		data = new(TestGroupState)
		data.Pods = make([]*api.Pod, 0)
		data.Services = make([]*api.Service, 0)
		t.state[key] = data
	}
	return data
}

func MockRemoveExpectedCall(m *mock.Mock, methodName string, arguments ...interface{}) bool {
	for i, call := range m.ExpectedCalls {
		if call.Method == methodName {
			_, difference := call.Arguments.Diff(arguments)
			if difference == 0 {
				m.ExpectedCalls = append(m.ExpectedCalls[:i], m.ExpectedCalls[i+1:]...)
				return true
			}
		}
	}
	return false
}

func podPtrSliceRemove(array []*api.Pod, element *api.Pod) []*api.Pod {
	for i, v := range array {
		if v == element {
			return append(array[:i], array[i+1:]...)
		}
	}
	return array
}

func servicePtrSliceRemove(array []*api.Service, element *api.Service) []*api.Service {
	for i, v := range array {
		if v == element {
			return append(array[:i], array[i+1:]...)
		}
	}
	return array
}

func (t *TestFramework) AddPod(pod *api.Pod) {
	state := t.GetGroupState(pod.Namespace, pod.Labels["Name"])
	state.Pods = append(state.Pods, pod)
	podsMock := t.kubeMock.Pods(pod.Namespace).(*mocks.KubePodInterface)
	podsMock.On("Update", pod).Return(pod, nil)

	key := pod.Namespace + "/" + pod.Name
	t.podStore.On("GetByKey", key).Return(pod, true, nil)
	t.keyList = append(t.keyList, key)

	t.controller.AddPod(pod)
}

func (t *TestFramework) DeletePod(pod *api.Pod) {
	state := t.GetGroupState(pod.Namespace, pod.Labels["Name"])
	state.Pods = podPtrSliceRemove(state.Pods, pod)
	podsMock := t.kubeMock.Pods(pod.Namespace).(*mocks.KubePodInterface)
	MockRemoveExpectedCall(&podsMock.Mock, "Update", pod)

	key := pod.Namespace + "/" + pod.Name
	MockRemoveExpectedCall(&t.podStore.Mock, "GetByKey", key)
	t.keyList = stringSliceRemove(t.keyList, key)

	t.controller.DeletePod(pod)
}

func (t *TestFramework) UpdatePod(oldPod, newPod *api.Pod) {
	state := t.GetGroupState(oldPod.Namespace, oldPod.Labels["Name"])
	state.Pods = podPtrSliceRemove(state.Pods, oldPod)
	state.Pods = append(state.Pods, newPod)

	podsMock := t.kubeMock.Pods(oldPod.Namespace).(*mocks.KubePodInterface)
	MockRemoveExpectedCall(&podsMock.Mock, "Update", oldPod)
	podsMock.On("Update", newPod).Return(newPod, nil)

	key := oldPod.Namespace + "/" + oldPod.Name
	MockRemoveExpectedCall(&t.podStore.Mock, "GetByKey", key)
	t.podStore.On("GetByKey", key).Return(newPod, true, nil)

	t.controller.UpdatePod(oldPod, newPod)
}

func (t *TestFramework) AddService(service *api.Service, groupName string) {
	state := t.GetGroupState(service.Namespace, groupName)
	state.Services = append(state.Services, service)
	podsMock := t.kubeMock.Pods(service.Namespace).(*mocks.KubePodInterface)
	selector := api.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set(service.Spec.Selector))}
	call := podsMock.On("List", selector).Return()
	call.Run(func(args mock.Arguments) {
		podList := make([]api.Pod, len(state.Pods))
		for i, v := range state.Pods {
			podList[i] = *v
		}
		call.Return(&api.PodList{Items: podList}, nil)
	})
	servicesMock := t.kubeMock.Services(service.Namespace).(*mocks.KubeServiceInterface)
	servicesMock.On("Update", service).Return(service, nil)
	t.serviceStore.On("GetByKey", service.Namespace+"/"+service.Name).Return(service, true, nil)

	t.controller.AddService(service)
}

func (t *TestFramework) DeleteService(service *api.Service, groupName string) {
	state := t.GetGroupState(service.Namespace, groupName)
	state.Services = servicePtrSliceRemove(state.Services, service)
	podsMock := t.kubeMock.Pods(service.Namespace).(*mocks.KubePodInterface)
	selector := api.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set(map[string]string{"Name": groupName}))}
	MockRemoveExpectedCall(&podsMock.Mock, "List", selector)
	servicesMock := t.kubeMock.Services(service.Namespace).(*mocks.KubeServiceInterface)
	MockRemoveExpectedCall(&servicesMock.Mock, "Update", service)
	MockRemoveExpectedCall(&t.serviceStore.Mock, "GetByKey", service.Namespace+"/"+service.Name)

	t.controller.DeleteService(service)
}

func (t *TestFramework) AllocateClusterIP(groupName string) string {
	var lowerBytes int
	for {
		lowerBytes = rand.Intn(16 * 1024)
		if _, exists := t.clusterIPs[lowerBytes]; !exists {
			t.clusterIPs[lowerBytes] = groupName
			break
		}
	}

	address, _ := PrefixToAddressLen(t.config.ServiceSubnet)
	bytes := strings.Split(address, ".")
	bytes[2] = strconv.Itoa(lowerBytes >> 8)
	bytes[3] = strconv.Itoa(lowerBytes & 255)
	return strings.Join(bytes, ".")
}

func (t *TestFramework) ReleaseClusterIP(address string) {
	bytes := strings.Split(address, ".")
	hi, _ := strconv.Atoi(bytes[2])
	lo, _ := strconv.Atoi(bytes[3])
	lowerBytes := hi*256 + lo
	delete(t.clusterIPs, lowerBytes)
}

type VmiInterceptor struct{}

func (v *VmiInterceptor) Get(ptr contrail.IObject) {
	nic := ptr.(*types.VirtualMachineInterface)
	mac := nic.GetVirtualMachineInterfaceMacAddresses()
	if len(mac.MacAddress) == 0 {
		mac.AddMacAddress("00:01:02:03:04:05")
		nic.SetVirtualMachineInterfaceMacAddresses(&mac)
	}
}

func (v *VmiInterceptor) Put(ptr contrail.IObject) {
}

type NetworkInterceptor struct{}

func (i *NetworkInterceptor) Put(ptr contrail.IObject) {
	network := ptr.(*types.VirtualNetwork)
	refs, err := network.GetNetworkIpamRefs()
	if err != nil || len(refs) == 0 {
		glog.Infof("%s: no ipam refs", network.GetName())
		return
	}

	attr := refs[0].Attr.(types.VnSubnetsType)
	if len(attr.IpamSubnets) == 0 {
		glog.Infof("%s: no subnets", network.GetName())
		return
	}

	attr.IpamSubnets[0].DefaultGateway = "1.1.1.1"
}

func (i *NetworkInterceptor) Get(ptr contrail.IObject) {
}
