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
	"github.com/golang/glog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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

	controller.config = NewConfig()

	controller.client = client
	if allocator == nil {
		controller.allocator = NewAddressAllocator(client, controller.config)
	} else {
		controller.allocator = allocator
	}
	controller.instanceMgr = NewInstanceManager(client, controller.allocator)
	if networkMgr == nil {
		controller.networkMgr = NewNetworkManager(client, controller.config)
	} else {
		controller.networkMgr = networkMgr
	}
	controller.serviceMgr = NewServiceManager(client, controller.config, controller.networkMgr)
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

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod)

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

	netnsProject := new(types.Project)
	netnsProject.SetUuid(uuid.New())
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	assert.NoError(t, client.Create(netnsProject))

	instance := new(types.VirtualMachine)
	fqn := []string{"default-domain", "testns", "test"}
	instance.SetFQName("project", fqn)
	instance.SetUuid(string(pod.ObjectMeta.UID))
	assert.NoError(t, client.Create(instance))

	vmi := new(types.VirtualMachineInterface)
	vmi.SetFQName("project", fqn)
	vmi.AddVirtualMachine(instance)
	assert.NoError(t, client.Create(vmi))

	ipObj := new(types.InstanceIp)
	ipObj.SetName("testns_test")
	assert.NoError(t, client.Create(ipObj))

	allocator.On("ReleaseIpAddress", string(pod.ObjectMeta.UID)).Return()
	networkMgr.On("ReleaseNetworkIfEmpty", "testns", "testnet").Return(true, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.DeletePod(pod)

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

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddNamespace(namespace)

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

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.DeleteNamespace(namespace)

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
	client.AddInterceptor("virtual-network", &NetworkInterceptor{})

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	assert.NoError(t, client.Create(netnsProject))

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)

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

	allocator.On("LocateIpAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.1", nil)

	kube.PodInterface.On("Update", pod).Return(pod, nil)
	kube.PodInterface.On("List", mock.Anything, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod)
	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	time.Sleep(100 * time.Millisecond)

	obj, err := client.FindByName("virtual-network", "default-domain:testns:service-x1")
	require.NoError(t, err)
	serviceNet := obj.(*types.VirtualNetwork)
	sip, err := controller.networkMgr.LocateFloatingIp(serviceNet, service.Name, service.Spec.ClusterIP)
	assert.NoError(t, err)
	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)
}

func TestPodAddWithService(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	client.AddInterceptor("virtual-network", &NetworkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
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

	allocator.On("LocateIpAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.1", nil)

	kube.PodInterface.On("Update", pod).Return(pod, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.serviceStore.Add(service)
	controller.AddPod(pod)

	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	kube.PodInterface.AssertExpectations(t)

	obj, err := client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.NoError(t, err)
	serviceNet := obj.(*types.VirtualNetwork)
	sip, err := controller.networkMgr.LocateFloatingIp(serviceNet, service.Name, service.Spec.ClusterIP)
	assert.NoError(t, err)
	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)
}

func TestServiceDeleteWithPod(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	client.AddInterceptor("virtual-network", &NetworkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testpod",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
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

	allocator.On("LocateIpAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("LocateIpAddress", string(pod2.ObjectMeta.UID)).Return("10.0.0.2", nil)

	kube.PodInterface.On("Update", pod1).Return(pod1, nil)
	kube.PodInterface.On("Update", pod2).Return(pod2, nil)
	kube.PodInterface.On("List", mock.Anything, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1, *pod2}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddPod(pod2)
	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)

	obj, err := client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.NoError(t, err)
	serviceNet := obj.(*types.VirtualNetwork)
	sip, err := controller.networkMgr.LocateFloatingIp(serviceNet, service.Name, service.Spec.ClusterIP)
	sipName := sip.GetFQName()
	assert.NoError(t, err)
	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)

	obj, err = client.FindByName("network-policy", "default-domain:testns:x1")
	assert.NoError(t, err)

	controller.DeleteService(service)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	obj, err = client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.Error(t, err)

	obj, err = client.FindByName("floating-ip", strings.Join(sipName, ":"))
	assert.Error(t, err)

	obj, err = client.FindByName("network-policy", "default-domain:testns:x1")
	assert.Error(t, err)
}

func TestPodUsesService(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	client.AddInterceptor("virtual-network", &NetworkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testpod",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "client",
				"uses": "x1",
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

	allocator.On("LocateIpAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("LocateIpAddress", string(pod2.ObjectMeta.UID)).Return("10.0.0.2", nil)

	allocator.On("ReleaseIpAddress", string(pod1.ObjectMeta.UID)).Return()
	allocator.On("ReleaseIpAddress", string(pod2.ObjectMeta.UID)).Return()

	kube.PodInterface.On("Update", pod1).Return(pod1, nil)
	kube.PodInterface.On("Update", pod2).Return(pod2, nil)
	kube.PodInterface.On("List", mock.Anything, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddService(service)
	time.Sleep(100 * time.Millisecond)

	policy, err := types.NetworkPolicyByName(client, "default-domain:testns:x1")
	policyId := policy.GetUuid()
	assert.NoError(t, err)

	serviceNet, err := types.VirtualNetworkByName(client, "default-domain:testns:service-x1")
	assert.NoError(t, err)

	poRefs, err := serviceNet.GetNetworkPolicyRefs()
	assert.NoError(t, err)
	assert.NotEmpty(t, poRefs)
	assert.Equal(t, policy.GetUuid(), poRefs[0].Uuid)

	controller.AddPod(pod2)
	time.Sleep(100 * time.Millisecond)

	clientNet, err := types.VirtualNetworkByName(client, "default-domain:testns:client")
	assert.NoError(t, err)

	clientRefs, err := clientNet.GetNetworkPolicyRefs()
	assert.NoError(t, err)
	assert.NotEmpty(t, clientRefs)
	assert.Equal(t, policy.GetUuid(), clientRefs[0].Uuid)

	controller.DeleteService(service)
	time.Sleep(100 * time.Millisecond)

	_, err = client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.Error(t, err)

	policy, err = types.NetworkPolicyByName(client, "default-domain:testns:x1")
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, policyId, policy.GetUuid())
		refs, err := policy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 1)
	}

	controller.AddService(service)
	time.Sleep(100 * time.Millisecond)

	policy, err = types.NetworkPolicyByName(client, "default-domain:testns:x1")
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, policyId, policy.GetUuid())
		refs, err := policy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 2)
	}

	controller.DeleteService(service)
	controller.DeletePod(pod1)
	controller.DeletePod(pod2)
	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	_, err = types.NetworkPolicyByName(client, "default-domain:testns:x1")
	assert.Error(t, err)
}

func TestPodUsesServiceCreatedAfter(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	client.AddInterceptor("virtual-network", &NetworkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testpod",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "client",
				"uses": "x1",
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

	allocator.On("LocateIpAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("LocateIpAddress", string(pod2.ObjectMeta.UID)).Return("10.0.0.2", nil)
	allocator.On("ReleaseIpAddress", string(pod1.ObjectMeta.UID)).Return()
	allocator.On("ReleaseIpAddress", string(pod2.ObjectMeta.UID)).Return()

	kube.PodInterface.On("Update", pod1).Return(pod1, nil)
	kube.PodInterface.On("Update", pod2).Return(pod2, nil)
	kube.PodInterface.On("List", mock.Anything, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod2)
	time.Sleep(100 * time.Millisecond)

	policy, err := types.NetworkPolicyByName(client, "default-domain:testns:x1")
	assert.NoError(t, err)

	clientNet, err := types.VirtualNetworkByName(client, "default-domain:testns:client")
	assert.NoError(t, err)

	clientRefs, err := clientNet.GetNetworkPolicyRefs()
	assert.NoError(t, err)
	assert.NotEmpty(t, clientRefs)
	assert.Equal(t, policy.GetUuid(), clientRefs[0].Uuid)

	controller.AddPod(pod1)
	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)

	serviceNet, err := types.VirtualNetworkByName(client, "default-domain:testns:service-x1")
	assert.NoError(t, err)

	poRefs, err := serviceNet.GetNetworkPolicyRefs()
	assert.NoError(t, err)
	assert.NotEmpty(t, poRefs)
	assert.Equal(t, policy.GetUuid(), poRefs[0].Uuid)

	controller.DeletePod(pod1)
	controller.DeletePod(pod2)
	controller.DeleteService(service)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	_, err = client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.Error(t, err)

	_, err = client.FindByName("network-policy", "default-domain:testns:x1")
	assert.Error(t, err)

	allocator.AssertExpectations(t)
}

func TestPodUsesNonExistingService(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &VmiInterceptor{})
	client.AddInterceptor("virtual-network", &NetworkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"name": "testpod",
				"uses": "nonexisting",
			},
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	allocator.On("LocateIpAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("ReleaseIpAddress", string(pod1.ObjectMeta.UID)).Return()
	kube.PodInterface.On("Update", pod1).Return(pod1, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	time.Sleep(100 * time.Millisecond)

	_, err := types.NetworkPolicyByName(client, "default-domain:testns:nonexisting")
	assert.NoError(t, err)

	_, err = types.VirtualNetworkByName(client, "default-domain:testns:testpod")
	assert.NoError(t, err)

	controller.DeletePod(pod1)
	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	_, err = types.VirtualNetworkByName(client, "default-domain:testns:testpod")
	assert.Error(t, err)

	_, err = types.NetworkPolicyByName(client, "default-domain:testns:nonexisting")
	assert.Error(t, err)

	allocator.AssertExpectations(t)
}
