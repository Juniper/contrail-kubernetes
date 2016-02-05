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
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"k8s.io/kubernetes/pkg/api"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
	kubetypes "k8s.io/kubernetes/pkg/types"

	"github.com/Juniper/contrail-kubernetes/pkg/network/opencontrail/mocks"
)

func newTestConsistencyChecker(controller *Controller) (ConsistencyChecker, *mocks.Store, *mocks.Store) {
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	controller.SetPodStore(podStore)
	controller.SetServiceStore(serviceStore)

	checker := NewConsistencyChecker(controller.client, controller.config, podStore, serviceStore, controller.networkMgr, controller.serviceMgr)
	return checker, podStore, serviceStore
}

func TestConsistencyMissingVM(t *testing.T) {
	client := createTestClient()
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil, nil)

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
		},
	}

	kube := mocks.NewKubeClient()
	controller := NewTestController(kube, client, nil, nil)

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	kube.PodInterface.On("Update", pod1).Return(pod1, nil)
	kube.PodInterface.On("Update", pod2).Return(pod2, nil)

	podStore.On("ListKeys").Return([]string{"testns/test-sv1", "testns/test-sv2"})
	podStore.On("GetByKey", "testns/test-sv1").Return(pod1, true, nil)
	podStore.On("GetByKey", "testns/test-sv2").Return(pod2, true, nil)
	serviceStore.On("List").Return([]interface{}{})

	shutdown := make(chan struct{})
	go controller.Run(shutdown)
	controller.AddPod(pod1)
	controller.AddPod(pod2)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	assert.True(t, checker.Check())

	vmi, err := types.VirtualMachineInterfaceByName(client, "default-domain:testns:test-sv1")
	assert.NoError(t, err)
	if err == nil {
		vmi.ClearVirtualMachine()
		err = client.Update(vmi)
		assert.NoError(t, err)
	}
	vm, err := types.VirtualMachineByName(client, "default-domain:testns:test-sv1")
	assert.NoError(t, err)
	if err == nil {
		err = client.Delete(vm)
		assert.NoError(t, err)
	}
	assert.False(t, checker.Check())
}

func installPods(controller *Controller, podInterface, podStore *mock.Mock, namespace string, count int) {
	keys := make([]string, count)
	for i := 0; i < count; i++ {
		pod := &api.Pod{
			ObjectMeta: api.ObjectMeta{
				Name:      fmt.Sprintf("pod%02d", i),
				Namespace: namespace,
				UID:       kubetypes.UID(uuid.New()),
				Labels: map[string]string{
					"app": fmt.Sprintf("pod%02d", i),
				},
			},
		}
		key := fmt.Sprintf("%s/%s", namespace, pod.Name)
		keys[i] = key
		podStore.On("GetByKey", key).Return(pod, true, nil)
		podInterface.On("Update", pod).Return(pod, nil)
		podInterface.On("List", makeListOptSelector(pod.Labels)).Return(&api.PodList{Items: []api.Pod{*pod}}, nil)
		controller.AddPod(pod)
	}

	podStore.On("ListKeys").Return(keys)
}

func TestConsistencyStaleVM(t *testing.T) {
	client := createTestClient()
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil, nil)

	kube := mocks.NewKubeClient()
	controller := NewTestController(kube, client, nil, nil)

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	serviceStore.On("List").Return([]interface{}{})

	installPods(controller, &kube.PodInterface.Mock, &podStore.Mock, "testns", 3)
	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
	time.Sleep(100 * time.Millisecond)

	assert.True(t, checker.Check())

	p2 := new(types.Project)
	p2.SetFQName("domain", []string{"default-domain", "p2"})
	assert.NoError(t, client.Create(p2))

	vm := new(types.VirtualMachine)
	vm.SetFQName("project", []string{"default-domain", "p2", "x"})
	assert.NoError(t, client.Create(vm))
	assert.False(t, checker.Check())

	assert.NoError(t, client.Delete(vm))
	assert.True(t, checker.Check())

	vm = new(types.VirtualMachine)
	vm.SetFQName("project", []string{"default-domain", "testns", "pod03"})
	assert.NoError(t, client.Create(vm))
	assert.False(t, checker.Check())
}

func TestConsistencyMissingInterface(t *testing.T) {
	client := createTestClient()
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil, nil)

	kube := mocks.NewKubeClient()
	controller := NewTestController(kube, client, nil, nil)

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	installPods(controller, &kube.PodInterface.Mock, &podStore.Mock, "testns", 3)
	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
	time.Sleep(100 * time.Millisecond)

	serviceStore.On("List").Return([]interface{}{})
	assert.True(t, checker.Check())

	vmi, err := types.VirtualMachineInterfaceByName(client, "default-domain:testns:pod01")
	assert.NoError(t, err)
	refs, err := vmi.GetInstanceIpBackRefs()
	for _, ref := range refs {
		ip, err := types.InstanceIpByUuid(client, ref.Uuid)
		assert.NoError(t, err)
		ip.ClearVirtualMachineInterface()
		assert.NoError(t, client.Update(ip))
	}
	assert.NoError(t, client.Delete(vmi))

	assert.False(t, checker.Check())
}

func TestConsistencyStaleInterface(t *testing.T) {
	client := createTestClient()
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil, nil)

	kube := mocks.NewKubeClient()
	controller := NewTestController(kube, client, nil, nil)

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	installPods(controller, &kube.PodInterface.Mock, &podStore.Mock, "testns", 3)
	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
	time.Sleep(100 * time.Millisecond)

	serviceStore.On("List").Return([]interface{}{})
	assert.True(t, checker.Check())

	vmi := new(types.VirtualMachineInterface)
	vmi.SetFQName("project", []string{"default-domain", "testns", "pod03"})
	assert.NoError(t, client.Create(vmi))

	assert.False(t, checker.Check())
}

func TestConsistencyServiceIp(t *testing.T) {
	client := createTestClient()
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil, nil)

	kube := mocks.NewKubeClient()
	controller := NewTestController(kube, client, nil, nil)
	config := controller.config

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	installPods(controller, &kube.PodInterface.Mock, &podStore.Mock, "testns", 3)

	service1 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "services",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"app": "pod01",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeLoadBalancer,
		},
	}
	service2 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s2",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "services",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"app": "pod02",
			},
			ClusterIP:   "10.254.42.43",
			ExternalIPs: []string{"10.1.4.89"},
		},
	}
	service3 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s3",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "services",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"app": "pod01",
			},
			ClusterIP: "10.254.42.44",
		},
	}

	kube.ServiceInterface.On("Update", service1).Return(service1, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddService(service1)
	controller.AddService(service2)
	controller.AddService(service3)
	serviceStore.On("List").Return([]interface{}{service1, service2, service3})
	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
	time.Sleep(100 * time.Millisecond)

	assert.True(t, checker.Check())

	pool, err := types.FloatingIpPoolByName(client, "default-domain:testns:service-services:service-services")
	assert.NoError(t, err)
	vmi, err := types.VirtualMachineInterfaceByName(client, "default-domain:testns:pod01")
	assert.NoError(t, err)
	vip := new(types.FloatingIp)
	fqn := make([]string, len(pool.GetFQName())+1)
	copy(fqn, pool.GetFQName())
	fqn[len(pool.GetFQName())] = "s4"
	vip.SetFQName(vip.GetDefaultParentType(), fqn)
	vip.AddVirtualMachineInterface(vmi)
	assert.NoError(t, client.Create(vip))
	assert.False(t, checker.Check())

	assert.NoError(t, client.Delete(vip))
	assert.True(t, checker.Check())

	vip, err = types.FloatingIpByName(client, "default-domain:testns:service-services:service-services:s3")
	assert.NoError(t, err)
	assert.NoError(t, client.Delete(vip))

	assert.False(t, checker.Check())
}

func addPodToStore(pod *api.Pod, podInterface *mocks.KubePodInterface, podStore *mocks.Store, keys *[]string, times int) {
	key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	*keys = append(*keys, key)

	podStore.On("GetByKey", key).Return(pod, true, nil).Times(times)
	podInterface.On("Update", pod).Return(pod, nil)
}

func TestConsistencyConnectionsDelete(t *testing.T) {
	kube := mocks.NewKubeClient()
	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	config := controller.config
	checker, podStore, serviceStore := newTestConsistencyChecker(controller)

	config.ClusterServices = []string{"kube-system/dns", "kube-system/monitoring"}

	// 2 client pods in network "private"
	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod01",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "private",
				config.NetworkAccessTag: "tagA",
			},
		},
	}

	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod02",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "private",
				config.NetworkAccessTag: "tagB",
			},
		},
	}

	// The service pods for service tagA and tagB respectivly.
	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod03",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "svc-backend",
				"app":             "provider01",
			},
		},
	}

	pod4 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod04",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "svc-backend",
				"app":             "provider02",
			},
		},
	}

	// And the services
	service1 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "tagA",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"app": "provider01",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	service2 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "tagB",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"app": "provider02",
			},
			ClusterIP: "10.254.42.43",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	sysProject := new(types.Project)
	sysProject.SetFQName("domain", []string{"default-domain", "kube-system"})
	client.Create(sysProject)

	keys := make([]string, 0)
	for _, pod := range []*api.Pod{pod1, pod2, pod3, pod4} {
		addPodToStore(pod, kube.PodInterface, podStore, &keys, 0)
	}
	podStore.On("ListKeys").Return(keys).Once()

	serviceStore.On("List").Return([]interface{}{service1, service2})

	s1Pods := makeListOptSelector(map[string]string{"app": "provider01"})
	kube.PodInterface.On("List", s1Pods).Return(&api.PodList{Items: []api.Pod{*pod3}}, nil)

	s2Pods := makeListOptSelector(map[string]string{"app": "provider02"})
	kube.PodInterface.On("List", s2Pods).Return(&api.PodList{Items: []api.Pod{*pod4}}, nil)

	kube.ServiceInterface.On("Update", service1).Return(service1, nil)
	kube.ServiceInterface.On("Update", service2).Return(service2, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddPod(pod2)
	controller.AddPod(pod3)
	controller.AddPod(pod4)
	controller.AddService(service1)
	controller.AddService(service2)

	time.Sleep(100 * time.Millisecond)
	assert.True(t, checker.Check())

	controller.DeletePod(pod2)
	time.Sleep(100 * time.Millisecond)
	keys = append(keys[0:1], keys[2:]...)
	podStore.On("ListKeys").Return(keys)

	assert.False(t, checker.Check())
	assert.False(t, checker.Check())
	assert.True(t, checker.Check())

	config.ClusterServices = []string{"kube-system/dns"}

	assert.False(t, checker.Check())
	assert.False(t, checker.Check())
	assert.True(t, checker.Check())

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
}

func getNetworkServiceConnections(t *testing.T, client contrail.ApiClient, config *Config, namespace, networkName string) []string {
	network, err := types.VirtualNetworkByName(client, strings.Join([]string{config.DefaultDomain, namespace, networkName}, ":"))
	require.NoError(t, err)
	policyRefs, err := network.GetNetworkPolicyRefs()
	require.NoError(t, err)
	serviceList := make([]string, 0, len(policyRefs))
	for _, ref := range policyRefs {
		svc, err := serviceNameFromPolicyName(ref.To[2])
		if err != nil {
			continue
		}
		serviceList = append(serviceList, svc)
	}
	return serviceList
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

func TestConsistencyPodUpdateRemovePrev(t *testing.T) {
	kube := mocks.NewKubeClient()
	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	checker, podStore, serviceStore := newTestConsistencyChecker(controller)

	config := controller.config

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "x-1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client",
				config.NetworkAccessTag: "red",
			},
		},
	}

	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "x-2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client",
				config.NetworkAccessTag: "red",
			},
		},
	}

	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "redPod",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "red",
				config.NetworkTag: "redPrivate",
			},
		},
	}

	pod4 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "bluePod",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "blue",
				config.NetworkTag: "bluePrivate",
			},
		},
	}

	redService := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "red",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "red",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "red",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	blueService := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "blue",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "blue",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "blue",
			},
			ClusterIP: "10.254.42.43",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	selectRed := makeListOptSelector(map[string]string{"Name": "red"})
	kube.PodInterface.On("List", selectRed).Return(&api.PodList{Items: []api.Pod{*pod3}}, nil)
	selectBlue := makeListOptSelector(map[string]string{"Name": "blue"})
	kube.PodInterface.On("List", selectBlue).Return(&api.PodList{Items: []api.Pod{*pod4}}, nil)

	kube.ServiceInterface.On("Update", redService).Return(redService, nil)
	kube.ServiceInterface.On("Update", blueService).Return(blueService, nil)

	keys := make([]string, 0)
	addPodToStore(pod1, kube.PodInterface, podStore, &keys, 1*2)
	addPodToStore(pod2, kube.PodInterface, podStore, &keys, 2*2)
	for _, pod := range []*api.Pod{pod3, pod4} {
		addPodToStore(pod, kube.PodInterface, podStore, &keys, 0)
	}
	podStore.On("ListKeys").Return(keys)
	serviceStore.On("List").Return([]interface{}{redService, blueService})

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddService(redService)
	controller.AddPod(pod2)
	controller.AddPod(pod3)
	controller.AddPod(pod4)
	controller.AddService(blueService)

	time.Sleep(100 * time.Millisecond)

	serviceConnections := getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "red"}, serviceConnections)
	assert.True(t, checker.Check())
	policyName := makeServicePolicyName(config, "testns", "red")
	_, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)

	clonePodAndUpdateAccessTag := func(pod *api.Pod, color string) *api.Pod {
		newPod := new(api.Pod)
		*newPod = *pod
		newPod.Labels = make(map[string]string, 0)
		for k, v := range pod.Labels {
			newPod.Labels[k] = v
		}
		newPod.Labels[config.NetworkAccessTag] = color
		return newPod
	}

	// Update connections on pod1
	nPod1 := clonePodAndUpdateAccessTag(pod1, "blue")
	controller.UpdatePod(pod1, nPod1)
	podStore.On("GetByKey", "testns/"+nPod1.Name).Return(nPod1, true, nil)

	time.Sleep(100 * time.Millisecond)

	serviceConnections = getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "red", "blue"}, serviceConnections)
	assert.True(t, checker.Check(), "red and blue present")

	// Update connections on pod2
	// This will leave a stale connection to network red.
	nPod2 := clonePodAndUpdateAccessTag(pod2, "blue")
	controller.UpdatePod(pod2, nPod2)
	podStore.On("GetByKey", "testns/"+nPod2.Name).Return(nPod2, true, nil)

	time.Sleep(100 * time.Millisecond)
	serviceConnections = getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "red", "blue"}, serviceConnections)

	assert.False(t, checker.Check())

	controller.DeleteService(redService)
	MockRemoveExpectedCall(&serviceStore.Mock, "List")
	serviceStore.On("List").Return([]interface{}{blueService})
	time.Sleep(100 * time.Millisecond)

	// The second pass will delete the connection to network red.
	assert.False(t, checker.Check())
	serviceConnections = getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "blue"}, serviceConnections)

	assert.True(t, checker.Check())

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	_, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)
}

func TestGlobalNetworkConsistencyUpdateNetwork(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	checker, podStore, serviceStore := newTestConsistencyChecker(controller)

	config := controller.config
	config.GlobalNetworks = []string{"default-domain:cluster:global"}

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "server",
				config.NetworkTag: "backend",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client",
				config.NetworkAccessTag: "svc",
			},
		},
	}
	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "gPod",
			Namespace: "cluster",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "global",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "svc",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "server",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	clusterProject := new(types.Project)
	clusterProject.SetFQName("", []string{"default-domain", "cluster"})
	require.NoError(t, client.Create(clusterProject))

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	require.NoError(t, client.Create(netnsProject))

	keys := make([]string, 0)
	for _, pod := range []*api.Pod{pod1, pod2} {
		addPodToStore(pod, kube.PodInterface, podStore, &keys, 0)
	}
	addPodToStore(pod3, kube.PodInterface, podStore, &keys, 0)
	podStore.On("ListKeys").Return(keys)
	serviceStore.On("List").Return([]interface{}{service})

	kube.PodInterface.On("List", makeListOptSelector(service.Spec.Selector)).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddPod(pod2)
	controller.AddPod(pod3)
	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)

	// This connects the global-network policy with the respective network which is created after
	// the policy.
	assert.False(t, checker.Check())
	// It should be ok now.
	assert.True(t, checker.Check())

	policyName := makeGlobalNetworkPolicyName(config, []string{"default-domain", "cluster", "global"})
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	require.NoError(t, err)

	netRefs, err := policy.GetVirtualNetworkBackRefs()
	require.NoError(t, err)
	assert.Len(t, netRefs, 3)
	assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 2)

	controller.DeletePod(pod1)
	controller.DeletePod(pod2)
	controller.DeleteService(service)
	time.Sleep(100 * time.Microsecond)

	_, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)

	MockRemoveExpectedCall(&podStore.Mock, "ListKeys")
	podStore.On("ListKeys").Return([]string{"cluster/gPod"})
	MockRemoveExpectedCall(&serviceStore.Mock, "List")
	serviceStore.On("List").Return([]interface{}{})
	assert.True(t, checker.Check())

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
}

func TestGlobalNetworkConsistencyConfigChange(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	checker, podStore, serviceStore := newTestConsistencyChecker(controller)

	config := controller.config
	config.GlobalNetworks = []string{"default-domain:cluster:global"}

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "server",
				config.NetworkTag: "backend",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client",
				config.NetworkAccessTag: "svc",
			},
		},
	}
	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "gPod",
			Namespace: "cluster",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "global",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "svc",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "server",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	clusterProject := new(types.Project)
	clusterProject.SetFQName("", []string{"default-domain", "cluster"})
	require.NoError(t, client.Create(clusterProject))

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	require.NoError(t, client.Create(netnsProject))

	keys := make([]string, 0)
	for _, pod := range []*api.Pod{pod1, pod2} {
		addPodToStore(pod, kube.PodInterface, podStore, &keys, 0)
	}
	addPodToStore(pod3, kube.PodInterface, podStore, &keys, 0)
	podStore.On("ListKeys").Return(keys)
	serviceStore.On("List").Return([]interface{}{service})

	kube.PodInterface.On("List", makeListOptSelector(service.Spec.Selector)).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod3)
	controller.AddPod(pod1)
	controller.AddPod(pod2)
	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)

	assert.True(t, checker.Check())

	config.GlobalNetworks = []string{}
	for i := 0; i < 2; i++ {
		assert.False(t, checker.Check())
	}

	assert.True(t, checker.Check())

	policyName := makeGlobalNetworkPolicyName(config, []string{"default-domain", "cluster", "global"})
	_, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	require.Error(t, err)

	controller.DeletePod(pod1)
	controller.DeletePod(pod2)
	controller.DeletePod(pod3)
	controller.DeleteService(service)
	time.Sleep(100 * time.Microsecond)

	MockRemoveExpectedCall(&podStore.Mock, "ListKeys")
	podStore.On("ListKeys").Return([]string{})
	MockRemoveExpectedCall(&serviceStore.Mock, "List")
	serviceStore.On("List").Return([]interface{}{})

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	assert.True(t, checker.Check())
}
