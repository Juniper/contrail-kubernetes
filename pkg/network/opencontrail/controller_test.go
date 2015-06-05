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
	"strings"
	"testing"
	"time"

	"code.google.com/p/go-uuid/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	kubeclient "github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"
	kubetypes "github.com/GoogleCloudPlatform/kubernetes/pkg/types"

	"github.com/Juniper/contrail-go-api"
	contrail_mocks "github.com/Juniper/contrail-go-api/mocks"
	"github.com/Juniper/contrail-go-api/types"

	"github.com/Juniper/contrail-kubernetes/pkg/network/opencontrail/mocks"
)

func testKeyFunc(obj interface{}) (string, error) {
	return "", nil
}

func NewTestController(kube kubeclient.Interface, client contrail.ApiClient, allocator AddressAllocator, networkMgr NetworkManager) *Controller {
	controller := new(Controller)
	controller.serviceStore = cache.NewStore(testKeyFunc)
	controller.eventChannel = make(chan notification, 32)
	controller.kube = kube

	config := new(Config)
	controller.config = NewConfig()

	config.PrivateSubnet = "10.0.0.0/16"
	config.ServiceSubnet = "10.254.0.0/16"
	controller.client = client
	controller.allocator = allocator
	controller.instanceMgr = NewInstanceManager(client, controller.allocator)
	controller.networkMgr = networkMgr
	controller.serviceMgr = NewServiceManager(client, config, networkMgr)
	controller.namespaceMgr = NewNamespaceManager(client)
	return controller
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

func TestPodCreate(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)

	controller := NewTestController(kube, client, allocator, networkMgr)
	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testnet",
			},
		},
	}
	netnsProject := new(types.Project)
	netnsProject.SetUuid(uuid.New())
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	testnet := new(types.VirtualNetwork)
	testnet.SetFQName("project", []string{"default-domain", "testns", "testnet"})
	client.Create(testnet)

	allocator.On("LocateIpAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.42", nil)
	networkMgr.On("LocateNetwork", "testns", "testnet",
		controller.config.PrivateSubnet).Return(testnet, nil)
	networkMgr.On("GetGatewayAddress", testnet).Return("10.0.255.254", nil)

	kube.PodInterface.On("Update", pod).Return(pod, nil)

	controller.AddPod(pod)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	kube.PodInterface.AssertExpectations(t)
}

func TestPodDelete(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)
	controller := NewTestController(nil, client, allocator, networkMgr)

	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testnet",
			},
		},
	}

	instance := new(types.VirtualMachine)
	fqn := []string{"default-domain", "testns", "test"}
	instance.SetFQName("project", fqn)
	instance.SetUuid(string(pod.ObjectMeta.UID))
	client.Create(instance)

	vmi := new(types.VirtualMachineInterface)
	vmi.SetFQName("project", fqn)
	client.Create(vmi)

	ipObj := new(types.InstanceIp)
	ipObj.SetName("testns_test")
	client.Create(ipObj)

	fip := new(types.FloatingIp)
	fipFQN := []string{"default-domain", "testns", "service-net", "service-pool", "test"}
	fip.SetFQName("floating-ip-pool", fipFQN)
	client.Create(fip)

	allocator.On("ReleaseIpAddress", string(pod.ObjectMeta.UID)).Return()

	controller.DeletePod(pod)
	shutdown := make(chan struct{})
	go controller.Run(shutdown)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	if obj, err := client.FindByName("virtual-machine", strings.Join(fqn, ":")); err == nil {
		t.Errorf("virtual-machine object still present %s", obj.GetUuid())
	}
	if obj, err := client.FindByUuid("virtual-machine-interface", vmi.GetUuid()); err == nil {
		t.Errorf("virtual-machine-interface object still present %s", obj.GetUuid())
	}
	if obj, err := client.FindByUuid("instance-ip", ipObj.GetUuid()); err == nil {
		t.Errorf("instance-ip object still present %s", obj.GetUuid())
	}
	// The floating-ip will not be deleted since we don't currently have a
	// good way to set the vmi floating-ip back refs.
	allocator.AssertExpectations(t)
}

func TestNamespaceAdd(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)
	controller := NewTestController(nil, client, allocator, networkMgr)

	namespace := &api.Namespace{
		ObjectMeta: api.ObjectMeta{
			Name: "netns",
			UID:  kubetypes.UID(uuid.New()),
		},
	}

	controller.AddNamespace(namespace)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	obj, err := client.FindByUuid("project", string(namespace.ObjectMeta.UID))
	if err != nil {
		t.Fatalf("Namespace %s: Not found", string(namespace.ObjectMeta.UID))
	}
	assert.Equal(t, namespace.Name, obj.GetName())
}

func TestNamespaceDelete(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)
	controller := NewTestController(nil, client, allocator, networkMgr)

	namespace := &api.Namespace{
		ObjectMeta: api.ObjectMeta{
			Name: "netns",
			UID:  kubetypes.UID(uuid.New()),
		},
	}

	project := new(types.Project)
	project.SetFQName("domain", []string{DefaultDomain, "netns"})
	project.SetUuid(string(namespace.ObjectMeta.UID))
	client.Create(project)

	controller.DeleteNamespace(namespace)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	_, err := client.FindByUuid("project", string(namespace.ObjectMeta.UID))
	assert.NotNil(t, err)
}

func TestServiceAddWithPod(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)

	controller := NewTestController(kube, client, allocator, networkMgr)
	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testpod",
			},
		},
	}
	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				"name": "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"name": "testpod",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	testnet := new(types.VirtualNetwork)
	testnet.SetFQName("project", []string{"default-domain", "testns", "testpod"})
	client.Create(testnet)
	networkMgr.On("LocateNetwork", "testns", "testpod",
		controller.config.PrivateSubnet).Return(testnet, nil)
	networkMgr.On("GetGatewayAddress", testnet).Return("10.0.255.254", nil)
	allocator.On("LocateIpAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.1", nil)

	servicenet := new(types.VirtualNetwork)
	servicenet.SetFQName("project", []string{"default-domain", "testns", "service-x1"})
	client.Create(servicenet)
	networkMgr.On("LocateNetwork", "testns", "service-x1", controller.config.ServiceSubnet).Return(servicenet, nil)
	pool := new(types.FloatingIpPool)
	pool.SetFQName("virtual-network", []string{DefaultDomain, "testns", "service-x1", "service-x1"})
	client.Create(pool)
	networkMgr.On("LocateFloatingIpPool", servicenet, controller.config.ServiceSubnet).Return(pool, nil)
	sip := new(types.FloatingIp)
	sip.SetFQName("floating-ip-pool", []string{DefaultDomain, "testns", "service-x1", "service-x1", service.Name})
	client.Create(sip)
	networkMgr.On("LocateFloatingIp", servicenet, service.Name, service.Spec.ClusterIP).Return(sip, nil)

	kube.PodInterface.On("Update", pod).Return(pod, nil)
	kube.PodInterface.On("List", mock.Anything, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod}}, nil)
	controller.AddPod(pod)
	controller.AddService(service)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)
}

func TestPodAddWithService(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)

	controller := NewTestController(kube, client, allocator, networkMgr)
	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testpod",
			},
		},
	}
	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				"name": "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"name": "testpod",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	testnet := new(types.VirtualNetwork)
	testnet.SetFQName("project", []string{"default-domain", "testns", "testpod"})
	client.Create(testnet)
	networkMgr.On("LocateNetwork", "testns", "testpod",
		controller.config.PrivateSubnet).Return(testnet, nil)
	networkMgr.On("GetGatewayAddress", testnet).Return("10.0.255.254", nil)
	allocator.On("LocateIpAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.1", nil)

	servicenet := new(types.VirtualNetwork)
	servicenet.SetFQName("project", []string{"default-domain", "testns", "service-x1"})
	client.Create(servicenet)
	networkMgr.On("LocateNetwork", "testns", "service-x1", controller.config.ServiceSubnet).Return(servicenet, nil)
	pool := new(types.FloatingIpPool)
	pool.SetFQName("virtual-network", []string{DefaultDomain, "testns", "service-x1", "service-x1"})
	client.Create(pool)
	networkMgr.On("LocateFloatingIpPool", servicenet, controller.config.ServiceSubnet).Return(pool, nil)
	sip := new(types.FloatingIp)
	sip.SetFQName("floating-ip-pool", []string{DefaultDomain, "testns", "service-x1", "service-x1", service.Name})
	client.Create(sip)
	networkMgr.On("LocateFloatingIp", servicenet, service.Name, service.Spec.ClusterIP).Return(sip, nil)

	kube.PodInterface.On("Update", pod).Return(pod, nil)
	controller.serviceStore.Add(service)
	controller.AddPod(pod)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)

}
