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
	"testing"
	"time"

	"code.google.com/p/go-uuid/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/labels"

	"github.com/Juniper/contrail-go-api/types"
	kubetypes "k8s.io/kubernetes/pkg/types"

	"github.com/Juniper/contrail-kubernetes/pkg/network/opencontrail/mocks"
)

func TestConsistencyMissingVM(t *testing.T) {
	client := createTestClient()
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil)

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
		selector := labels.Set(pod.Labels).AsSelector()
		podInterface.On("List", selector, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod}}, nil)
		controller.AddPod(pod)
	}

	podStore.On("ListKeys").Return(keys)
}

func TestConsistencyStaleVM(t *testing.T) {
	client := createTestClient()
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil)

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
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil)

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
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil)

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
	checker := NewConsistencyChecker(client, NewConfig(), podStore, serviceStore, nil)

	kube := mocks.NewKubeClient()
	controller := NewTestController(kube, client, nil, nil)

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	installPods(controller, &kube.PodInterface.Mock, &podStore.Mock, "testns", 3)

	service1 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				"name": "services",
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
				"name": "services",
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
				"name": "services",
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

func addPod(pod *api.Pod, podInterface *mocks.KubePodInterface, podStore *mocks.Store, keys *[]string) {
	key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	*keys = append(*keys, key)

	podStore.On("GetByKey", key).Return(pod, true, nil)
	podInterface.On("Update", pod).Return(pod, nil)
}

func TestConsistencyConnectionsDelete(t *testing.T) {
	podStore := new(mocks.Store)
	serviceStore := new(mocks.Store)

	kube := mocks.NewKubeClient()
	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	controller.SetPodStore(podStore)
	controller.SetServiceStore(serviceStore)

	checker := NewConsistencyChecker(client, controller.config, podStore, serviceStore, controller.serviceMgr)

	controller.config.ClusterServices = []string{"kube-system/dns", "kube-system/monitoring"}

	// 2 client pods in network "private"
	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod01",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "private",
				"uses": "tagA",
			},
		},
	}

	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod02",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "private",
				"uses": "tagB",
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
				"name": "svc-backend",
				"app":  "provider01",
			},
		},
	}

	pod4 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod04",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "svc-backend",
				"app":  "provider02",
			},
		},
	}

	// And the services
	service1 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service1",
			Namespace: "testns",
			Labels: map[string]string{
				"name": "tagA",
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
				"name": "tagB",
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
	addPod(pod1, kube.PodInterface, podStore, &keys)
	addPod(pod2, kube.PodInterface, podStore, &keys)
	addPod(pod3, kube.PodInterface, podStore, &keys)
	addPod(pod4, kube.PodInterface, podStore, &keys)
	podStore.On("ListKeys").Return(keys).Once()

	serviceStore.On("List").Return([]interface{}{service1, service2})

	s1Pods := labels.Set(map[string]string{"app": "provider01"}).AsSelector()
	kube.PodInterface.On("List", s1Pods, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod3}}, nil)

	s2Pods := labels.Set(map[string]string{"app": "provider02"}).AsSelector()
	kube.PodInterface.On("List", s2Pods, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod4}}, nil)

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

	controller.config.ClusterServices = []string{"kube-system/dns"}

	assert.False(t, checker.Check())
	assert.False(t, checker.Check())
	assert.True(t, checker.Check())

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
}
