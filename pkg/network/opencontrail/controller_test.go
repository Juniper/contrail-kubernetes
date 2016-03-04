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

	"github.com/golang/glog"
	"github.com/pborman/uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	kubeclient "k8s.io/kubernetes/pkg/client/unversioned"
	kubetypes "k8s.io/kubernetes/pkg/types"

	"github.com/Juniper/contrail-go-api"
	contrail_mocks "github.com/Juniper/contrail-go-api/mocks"
	"github.com/Juniper/contrail-go-api/types"

	"github.com/Juniper/contrail-kubernetes/pkg/network/opencontrail/mocks"
)

func testKeyFunc(obj interface{}) (string, error) {
	return "", nil
}

func createTestClient() contrail.ApiClient {
	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})
	client.AddInterceptor("instance-ip", &ipInterceptor{})
	client.AddInterceptor("floating-ip", &floatingIPInterceptor{})
	return client
}

func NewTestController(kube kubeclient.Interface, client contrail.ApiClient, allocator AddressAllocator, networkMgr NetworkManager) *Controller {
	controller := new(Controller)
	controller.serviceStore = cache.NewStore(testKeyFunc)
	controller.eventChannel = make(chan notification, 32)
	controller.kube = kube

	controller.config = NewConfig()
	controller.config.PublicSubnet = "100.64.0.0/10"

	controller.client = client
	if allocator == nil {
		controller.allocator = NewAddressAllocator(client, controller.config)
	} else {
		controller.allocator = allocator
	}
	controller.instanceMgr = NewInstanceManager(client, controller.config, controller.allocator)
	if networkMgr == nil {
		controller.networkMgr = NewNetworkManager(client, controller.config)
	} else {
		controller.networkMgr = networkMgr
	}
	controller.serviceMgr = NewServiceManager(client, controller.config, controller.networkMgr)
	controller.namespaceMgr = NewNamespaceManager(client, controller.config)
	return controller
}

func policyHasRule(policy *types.NetworkPolicy, lhsName, rhsName string) bool {
	entries := policy.GetNetworkPolicyEntries()
	for _, rule := range entries.PolicyRule {
		if rule.SrcAddresses[0].VirtualNetwork == lhsName &&
			rule.DstAddresses[0].VirtualNetwork == rhsName {
			return true
		}
	}
	return false
}
func TestPodCreate(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)

	controller := NewTestController(kube, client, allocator, networkMgr)
	config := controller.config
	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testnet",
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

	allocator.On("LocateIPAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.42", nil)
	networkMgr.On("LookupNetwork", "testns", "service-default").Return(nil, fmt.Errorf("404 Not found"))
	networkMgr.On("LocateNetwork", "testns", "testnet",
		controller.config.PrivateSubnet).Return(testnet, nil)
	networkMgr.On("GetGatewayAddress", testnet).Return("10.0.255.254", nil)

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod).Return(pod, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod)

	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	assert.True(t, controller.podAnnotationsCheck(pod))
	kube.Pods("testns").(*mocks.KubePodInterface).AssertExpectations(t)
}

func TestPodDelete(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()
	allocator := new(mocks.AddressAllocator)
	networkMgr := new(mocks.NetworkManager)
	controller := NewTestController(nil, client, allocator, networkMgr)
	config := controller.config

	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testnet",
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

	allocator.On("ReleaseIPAddress", string(pod.ObjectMeta.UID)).Return()
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
	project.SetFQName("domain", []string{controller.config.DefaultDomain, "netns"})
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

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	assert.NoError(t, client.Create(netnsProject))

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
	config := controller.config

	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testpod",
			},
		},
	}
	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "testpod",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	allocator.On("LocateIPAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.1", nil)

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod).Return(pod, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod}}, nil)

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
	sip, err := controller.networkMgr.LocateFloatingIP(serviceNet, service.Name, service.Spec.ClusterIP)
	assert.NoError(t, err)
	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)

	policyName := makeServicePolicyName(config, "testns", "x1")
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 0)
	}
}

func TestPodAddWithService(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
	config := controller.config

	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testpod",
			},
		},
	}
	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "testpod",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	allocator.On("LocateIPAddress", string(pod.ObjectMeta.UID)).Return("10.0.0.1", nil)

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod).Return(pod, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.serviceStore.Add(service)
	controller.AddPod(pod)

	time.Sleep(100 * time.Millisecond)
	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	kube.Pods("testns").(*mocks.KubePodInterface).AssertExpectations(t)

	obj, err := client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.NoError(t, err)
	serviceNet := obj.(*types.VirtualNetwork)
	sip, err := controller.networkMgr.LocateFloatingIP(serviceNet, service.Name, service.Spec.ClusterIP)
	assert.NoError(t, err)
	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)
}

func TestServiceDeleteWithPod(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
	config := controller.config

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testpod",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testpod",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "testpod",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	allocator.On("LocateIPAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("LocateIPAddress", string(pod2.ObjectMeta.UID)).Return("10.0.0.2", nil)

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1, *pod2}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddPod(pod2)
	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)

	obj, err := client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.NoError(t, err)
	serviceNet := obj.(*types.VirtualNetwork)
	sip, err := controller.networkMgr.LocateFloatingIP(serviceNet, service.Name, service.Spec.ClusterIP)
	sipName := sip.GetFQName()
	assert.NoError(t, err)
	refList, err := sip.GetVirtualMachineInterfaceRefs()
	assert.Nil(t, err)
	assert.NotEmpty(t, refList)

	policyName := makeServicePolicyName(config, "testns", "x1")
	obj, err = client.FindByName("network-policy", strings.Join(policyName, ":"))
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

	obj, err = client.FindByName("network-policy", strings.Join(policyName, ":"))
	assert.Error(t, err)
}

func TestPodUsesService(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
	config := controller.config
	config.NamespaceServices = nil

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testpod",
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
				config.NetworkAccessTag: "x1",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "testpod",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	allocator.On("LocateIPAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("LocateIPAddress", string(pod2.ObjectMeta.UID)).Return("10.0.0.2", nil)

	allocator.On("ReleaseIPAddress", string(pod1.ObjectMeta.UID)).Return()
	allocator.On("ReleaseIPAddress", string(pod2.ObjectMeta.UID)).Return()

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddService(service)
	time.Sleep(100 * time.Millisecond)

	policyName := makeServicePolicyName(config, "testns", "x1")
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	require.NoError(t, err)
	policyID := policy.GetUuid()
	assert.NoError(t, err)

	serviceNet, err := types.VirtualNetworkByName(client, "default-domain:testns:service-x1")
	assert.NoError(t, err)

	poRefs, err := serviceNet.GetNetworkPolicyRefs()
	if assert.NoError(t, err) && assert.NotEmpty(t, poRefs) {
		assert.Equal(t, policy.GetUuid(), poRefs[0].Uuid)
	}

	controller.AddPod(pod2)
	time.Sleep(100 * time.Millisecond)

	clientNet, err := types.VirtualNetworkByName(client, "default-domain:testns:client")
	assert.NoError(t, err)

	clientRefs, err := clientNet.GetNetworkPolicyRefs()
	if assert.NoError(t, err) && assert.NotEmpty(t, clientRefs) {
		assert.Equal(t, policy.GetUuid(), clientRefs[0].Uuid)
	}

	policy, err = types.NetworkPolicyByName(client, "default-domain:testns:x1")
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client", "default-domain:testns:service-x1"))
	}

	controller.DeleteService(service)
	time.Sleep(100 * time.Millisecond)

	_, err = client.FindByName("virtual-network", "default-domain:testns:service-x1")
	assert.Error(t, err)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, policyID, policy.GetUuid())
		refs, err := policy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 1)
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 0)
	}

	controller.AddService(service)
	time.Sleep(100 * time.Millisecond)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, policyID, policy.GetUuid())
		refs, err := policy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 2)
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client", "default-domain:testns:service-x1"))
	}

	controller.DeleteService(service)
	controller.DeletePod(pod1)
	controller.DeletePod(pod2)
	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	_, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)
}

func TestPodUsesServiceCreatedAfter(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
	config := controller.config
	config.NamespaceServices = nil

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "testpod",
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
				config.NetworkAccessTag: "x1",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "testpod",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	allocator.On("LocateIPAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("LocateIPAddress", string(pod2.ObjectMeta.UID)).Return("10.0.0.2", nil)
	allocator.On("ReleaseIPAddress", string(pod1.ObjectMeta.UID)).Return()
	allocator.On("ReleaseIPAddress", string(pod2.ObjectMeta.UID)).Return()

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod2)
	time.Sleep(100 * time.Millisecond)

	policyName := makeServicePolicyName(config, "testns", "x1")
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)

	clientNet, err := types.VirtualNetworkByName(client, "default-domain:testns:client")
	assert.NoError(t, err)

	clientRefs, err := clientNet.GetNetworkPolicyRefs()
	if assert.NoError(t, err) && assert.NotEmpty(t, clientRefs) && assert.NotNil(t, policy) {
		assert.Equal(t, policy.GetUuid(), clientRefs[0].Uuid)
	}

	controller.AddPod(pod1)
	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)

	serviceNet, err := types.VirtualNetworkByName(client, "default-domain:testns:service-x1")
	assert.NoError(t, err)

	poRefs, err := serviceNet.GetNetworkPolicyRefs()
	if assert.NoError(t, err) && assert.NotEmpty(t, poRefs) {
		assert.Equal(t, policy.GetUuid(), poRefs[0].Uuid)
	}

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client", "default-domain:testns:service-x1"))
	}

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

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
	config := controller.config
	config.NamespaceServices = nil

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "testpod",
				config.NetworkAccessTag: "nonexisting",
			},
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	allocator.On("LocateIPAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("ReleaseIPAddress", string(pod1.ObjectMeta.UID)).Return()
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	time.Sleep(100 * time.Millisecond)

	policyName := makeServicePolicyName(config, "testns", "nonexisting")
	_, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
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

	_, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)

	allocator.AssertExpectations(t)
}

func TestServiceWithMultipleUsers(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := new(contrail_mocks.ApiClient)
	client.Init()

	client.AddInterceptor("virtual-machine-interface", &vmiInterceptor{})
	client.AddInterceptor("virtual-network", &networkInterceptor{})

	allocator := new(mocks.AddressAllocator)

	controller := NewTestController(kube, client, allocator, nil)
	config := controller.config

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-server",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "server",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client1",
				config.NetworkAccessTag: "x1",
			},
		},
	}
	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client1",
				config.NetworkAccessTag: "x1",
			},
		},
	}
	pod4 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz3",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client2",
				config.NetworkAccessTag: "x1",
			},
		},
	}
	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "x1",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "server",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	allocator.On("LocateIPAddress", string(pod1.ObjectMeta.UID)).Return("10.0.0.1", nil)
	allocator.On("LocateIPAddress", string(pod2.ObjectMeta.UID)).Return("10.0.0.2", nil)
	allocator.On("LocateIPAddress", string(pod3.ObjectMeta.UID)).Return("10.0.0.3", nil)
	allocator.On("LocateIPAddress", string(pod4.ObjectMeta.UID)).Return("10.0.0.4", nil)
	allocator.On("ReleaseIPAddress", string(pod1.ObjectMeta.UID)).Return()
	allocator.On("ReleaseIPAddress", string(pod2.ObjectMeta.UID)).Return()
	allocator.On("ReleaseIPAddress", string(pod3.ObjectMeta.UID)).Return()
	allocator.On("ReleaseIPAddress", string(pod4.ObjectMeta.UID)).Return()

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod3).Return(pod3, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod4).Return(pod4, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddService(service)
	controller.AddPod(pod2)
	controller.AddPod(pod3)
	controller.AddPod(pod4)

	time.Sleep(100 * time.Millisecond)

	policyName := makeServicePolicyName(config, "testns", "x1")
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 2)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client1", "default-domain:testns:service-x1"))
		assert.True(t, policyHasRule(policy, "default-domain:testns:client2", "default-domain:testns:service-x1"))
	}

	_, err = types.VirtualNetworkByName(client, "default-domain:testns:client2")
	assert.NoError(t, err)

	controller.DeletePod(pod3)
	time.Sleep(100 * time.Millisecond)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 2)
	}

	controller.DeletePod(pod4)
	time.Sleep(100 * time.Millisecond)

	_, err = types.VirtualNetworkByName(client, "default-domain:testns:client2")
	assert.Error(t, err)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client1", "default-domain:testns:service-x1"))
	}

	controller.DeletePod(pod2)
	time.Sleep(100 * time.Millisecond)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 0)
	}

	controller.DeletePod(pod1)
	controller.DeleteService(service)
	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)
}

func TestServiceWithMultipleBackends(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	config.NamespaceServices = nil
	client := env.client

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "backend",
				config.NetworkTag: "backend",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "backend",
				config.NetworkTag: "backend",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "svc",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "backend",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()

	env.AddPod(pod1)
	env.AddService(service, "backend")
	time.Sleep(100 * time.Millisecond)

	env.AddPod(pod2)
	time.Sleep(100 * time.Millisecond)

	fip, err := types.FloatingIpByName(client, "default-domain:testns:service-svc:service-svc:service")
	assert.NoError(t, err)
	if err == nil {
		refs, err := fip.GetVirtualMachineInterfaceRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 2)
	}

	env.DeletePod(pod1)
	time.Sleep(100 * time.Millisecond)

	fip, err = types.FloatingIpByName(client, "default-domain:testns:service-svc:service-svc:service")
	assert.NoError(t, err)
	if err == nil {
		refs, err := fip.GetVirtualMachineInterfaceRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 1)
		var uids []string
		for _, ref := range refs {
			uids = append(uids, ref.Uuid)
		}
		vmi, err := types.VirtualMachineInterfaceByName(client, "default-domain:testns:test-sv2")
		assert.NoError(t, err)
		if err == nil {
			assert.Contains(t, uids, vmi.GetUuid())
		}
	}

	env.AddPod(pod1)
	time.Sleep(100 * time.Millisecond)

	fip, err = types.FloatingIpByName(client, "default-domain:testns:service-svc:service-svc:service")
	assert.NoError(t, err)
	if err == nil {
		refs, err := fip.GetVirtualMachineInterfaceRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 2)
	}

	env.DeletePod(pod1)
	env.DeletePod(pod2)
	time.Sleep(100 * time.Millisecond)

	fip, err = types.FloatingIpByName(client, "default-domain:testns:service-svc:service-svc:service")
	assert.NoError(t, err)
	if err == nil {
		refs, err := fip.GetVirtualMachineInterfaceRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 0)
	}

	env.DeleteService(service, "backend")
	time.Sleep(100 * time.Millisecond)

	env.Shutdown()

	_, err = types.FloatingIpByName(client, "default-domain:testns:service-svc:service-svc:service")
	assert.Error(t, err)
}

func TestServiceWithLoadBalancer(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	client := env.client

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "backend",
				config.NetworkTag: "backend",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "backend",
				config.NetworkTag: "backend",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "svc",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "backend",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeLoadBalancer,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()
	env.AddPod(pod1)
	env.AddService(service, "backend")
	time.Sleep(100 * time.Millisecond)

	env.AddPod(pod2)
	time.Sleep(100 * time.Millisecond)

	fqn := strings.Split(config.PublicNetwork, ":")
	fqn = append(fqn, fqn[len(fqn)-1])
	fqn = append(fqn, fmt.Sprintf("%s_%s", service.Namespace, service.Name))
	fip, err := types.FloatingIpByName(client, strings.Join(fqn, ":"))
	assert.NoError(t, err)
	if err == nil {
		refs, err := fip.GetVirtualMachineInterfaceRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 2)
	}

	env.DeleteService(service, "backend")
	time.Sleep(100 * time.Millisecond)

	env.Shutdown()

	_, err = types.FloatingIpByName(client, strings.Join(fqn, ":"))
	assert.Error(t, err)
}

func getFloatingIPToInstanceList(client contrail.ApiClient, fip *types.FloatingIp) ([]string, error) {
	var vmList []string
	refs, err := fip.GetVirtualMachineInterfaceRefs()
	if err != nil {
		return vmList, err
	}
	for _, ref := range refs {
		vmi, err := types.VirtualMachineInterfaceByUuid(client, ref.Uuid)
		if err != nil {
			continue
		}
		instanceRefs, err := vmi.GetVirtualMachineRefs()
		if err != nil || len(instanceRefs) == 0 {
			continue
		}
		vmList = append(vmList, instanceRefs[0].Uuid)
	}
	return vmList, nil
}

func getReferenceListNames(refs contrail.ReferenceList) []string {
	names := make([]string, 0, len(refs))
	for _, ref := range refs {
		names = append(names, strings.Join(ref.To, ":"))
	}
	return names
}

func TestServiceUpdateSelector(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	config := controller.config

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "red",
			},
		},
	}

	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "blue",
			},
		},
	}

	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz3",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client",
				config.NetworkAccessTag: "svc",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "svc",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "red",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeLoadBalancer,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod3).Return(pod3, nil)

	selectRed := makeListOptSelector(map[string]string{config.NetworkTag: "red"})
	selectBlue := makeListOptSelector(map[string]string{config.NetworkTag: "blue"})
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", selectRed).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", selectBlue).Return(&api.PodList{Items: []api.Pod{*pod2}}, nil)
	kube.Services("testns").(*mocks.KubeServiceInterface).On("Update", service).Return(service, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddPod(pod2)
	controller.AddPod(pod3)
	controller.AddService(service)
	time.Sleep(100 * time.Millisecond)

	serviceIP, err := types.FloatingIpByName(client, "default-domain:testns:service-svc:service-svc:service")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, serviceIP)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

	fqn := strings.Split(config.PublicNetwork, ":")
	fqn = append(fqn, fqn[len(fqn)-1])
	fqn = append(fqn, fmt.Sprintf("%s_%s", service.Namespace, service.Name))
	publicIP, err := types.FloatingIpByName(client, strings.Join(fqn, ":"))
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, publicIP)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

	nService := new(api.Service)
	*nService = *service
	nService.Spec.Selector = map[string]string{
		config.NetworkTag: "blue",
	}

	controller.UpdateService(service, nService)
	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	serviceIP, err = types.FloatingIpByName(client, "default-domain:testns:service-svc:service-svc:service")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, serviceIP)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod2.UID))
	}
	publicIP, err = types.FloatingIpByName(client, strings.Join(fqn, ":"))
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, publicIP)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod2.UID))
	}

	policyName := makeServicePolicyName(config, "testns", "svc")
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client", "default-domain:testns:service-svc"))
	}

}

func TestServiceUpdateLabel(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	client := env.client
	config.NamespaceServices = nil

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "server",
				config.NetworkTag: "server",
			},
		},
	}

	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":                  "client",
				config.NetworkTag:       "client1",
				config.NetworkAccessTag: "red",
			},
		},
	}

	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz3",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":                  "client",
				config.NetworkTag:       "client2",
				config.NetworkAccessTag: "blue",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "red",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "server",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeLoadBalancer,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()

	env.AddPod(pod1)
	env.AddPod(pod2)
	env.AddPod(pod3)
	env.AddService(service, "server")
	time.Sleep(100 * time.Millisecond)

	redPolicyName := makeServicePolicyName(config, "testns", "red")
	redPolicy, err := types.NetworkPolicyByName(client, strings.Join(redPolicyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, redPolicy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(redPolicy, "default-domain:testns:client1", "default-domain:testns:service-red"))
		refs, err := redPolicy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		nameList := getReferenceListNames(refs)
		assert.Contains(t, nameList, "default-domain:testns:client1")
		assert.Contains(t, nameList, "default-domain:testns:service-red")
	}

	bluePolicyName := makeServicePolicyName(config, "testns", "blue")
	bluePolicy, err := types.NetworkPolicyByName(client, strings.Join(bluePolicyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, bluePolicy.GetNetworkPolicyEntries().PolicyRule, 0)
		refs, err := bluePolicy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 1)
	}

	nService := new(api.Service)
	*nService = *service
	nService.Labels = map[string]string{
		config.NetworkTag: "blue",
	}
	// The service will receive a different PublicIP because this is translated into a service delete operation,
	// followed by an add.
	env.kubeMock.Services("testns").(*mocks.KubeServiceInterface).On("Update", nService).Return(nService, nil)

	env.controller.UpdateService(service, nService)
	time.Sleep(100 * time.Millisecond)

	env.Shutdown()

	bluePolicy, err = types.NetworkPolicyByName(client, strings.Join(bluePolicyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, bluePolicy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(bluePolicy, "default-domain:testns:client2", "default-domain:testns:service-blue"))
		refs, err := bluePolicy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		nameList := getReferenceListNames(refs)
		assert.Contains(t, nameList, "default-domain:testns:client2")
		assert.Contains(t, nameList, "default-domain:testns:service-blue")
	}

	redPolicy, err = types.NetworkPolicyByName(client, strings.Join(redPolicyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, redPolicy.GetNetworkPolicyEntries().PolicyRule, 0)
		refs, err := redPolicy.GetVirtualNetworkBackRefs()
		assert.NoError(t, err)
		assert.Len(t, refs, 1)
	}

	fip, err := types.FloatingIpByName(client, "default-domain:testns:service-blue:service-blue:service")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, fip)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

}

func TestServiceUpdatePublicIP(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	config := controller.config

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "service",
			},
		},
	}

	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "service",
			},
		},
	}

	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz3",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag:       "client",
				config.NetworkAccessTag: "svc",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "svc",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "service",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeLoadBalancer,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod3).Return(pod3, nil)
	selectPods := makeListOptSelector(map[string]string{config.NetworkTag: "service"})
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", selectPods).Return(&api.PodList{Items: []api.Pod{*pod1, *pod2}}, nil)
	kube.Services("testns").(*mocks.KubeServiceInterface).On("Update", service).Return(service, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddPod(pod2)
	controller.AddPod(pod3)
	controller.AddService(service)
	time.Sleep(100 * time.Millisecond)

	fqn := strings.Split(config.PublicNetwork, ":")
	fqn = append(fqn, fqn[len(fqn)-1])
	fqn = append(fqn, fmt.Sprintf("%s_%s", service.Namespace, service.Name))
	fip, err := types.FloatingIpByName(client, strings.Join(fqn, ":"))
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, fip)
		assert.NoError(t, err)
		assert.Len(t, vmList, 2)
		assert.Contains(t, vmList, string(pod1.UID))
		assert.Contains(t, vmList, string(pod2.UID))
	}

	nService := new(api.Service)
	*nService = *service
	nService.Spec.Type = api.ServiceTypeClusterIP

	controller.UpdateService(service, nService)
	time.Sleep(100 * time.Millisecond)

	_, err = types.FloatingIpByName(client, strings.Join(fqn, ":"))
	assert.Error(t, err)

	controller.UpdateService(nService, service)
	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}

	fip, err = types.FloatingIpByName(client, strings.Join(fqn, ":"))
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, fip)
		assert.NoError(t, err)
		assert.Len(t, vmList, 2)
		assert.Contains(t, vmList, string(pod1.UID))
		assert.Contains(t, vmList, string(pod2.UID))
	}

	policyName := makeServicePolicyName(config, "testns", "svc")
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client", "default-domain:testns:service-svc"))
	}

}

func TestNetworkWithMultipleServices(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	client := env.client

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "service1",
				"app":             "service1",
				config.NetworkTag: "internal-net",
			},
		},
	}

	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "service2",
				"app":             "service2",
				config.NetworkTag: "internal-net",
			},
		},
	}

	pod3 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-client",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":                  "client",
				config.NetworkTag:       "client",
				config.NetworkAccessTag: "common",
			},
		},
	}

	service1 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "common",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"app": "service1",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	service2 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service2",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "common",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"app": "service2",
			},
			ClusterIP: "10.254.42.43",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()

	env.AddPod(pod1)
	env.AddPod(pod2)
	env.AddPod(pod3)
	env.AddService(service1, "service1")
	env.AddService(service2, "service2")
	time.Sleep(100 * time.Millisecond)

	vip1, err := types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service1")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, vip1)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

	vip2, err := types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service2")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, vip2)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod2.UID))
	}

	policyName := makeServicePolicyName(config, "testns", "common")
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client", "default-domain:testns:service-common"))
	}

	env.DeleteService(service2, "service2")
	time.Sleep(100 * time.Millisecond)

	env.Shutdown()

	vip1, err = types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service1")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, vip1)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

	_, err = types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service2")
	assert.Error(t, err)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.NoError(t, err)
	if err == nil {
		assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)
		assert.True(t, policyHasRule(policy, "default-domain:testns:client", "default-domain:testns:service-common"))
	}
}

func TestPodSelectedBy2Services(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	client := env.client

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "svc",
				config.NetworkTag: "svc",
			},
		},
	}

	service1 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "common",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "svc",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	service2 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service2",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "common",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "svc",
			},
			ClusterIP: "10.254.42.43",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()

	env.AddPod(pod1)
	env.AddService(service1, "svc")
	env.AddService(service2, "svc")

	time.Sleep(100 * time.Millisecond)

	vip1, err := types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service1")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, vip1)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

	vip2, err := types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service2")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, vip2)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

	env.DeleteService(service2, "svc")
	time.Sleep(100 * time.Millisecond)

	env.Shutdown()

	vip1, err = types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service1")
	assert.NoError(t, err)
	if err == nil {
		vmList, err := getFloatingIPToInstanceList(client, vip1)
		assert.NoError(t, err)
		assert.Len(t, vmList, 1)
		assert.Contains(t, vmList, string(pod1.UID))
	}

	_, err = types.FloatingIpByName(client, "default-domain:testns:service-common:service-common:service2")
	assert.Error(t, err)
}

func TestPodUsing2Services(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	config.NamespaceServices = nil
	client := env.client

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-sv1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "private",
				config.NetworkTag: "private",
			},
			Annotations: map[string]string{
				config.NetworkAccessTag: "[\"foo\", \"bar\"]",
			},
		},
	}

	service1 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "foo",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "app1",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	service2 := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service2",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag: "bar",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "app2",
			},
			ClusterIP: "10.254.42.43",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()

	env.AddPod(pod1)
	env.AddService(service1, "app1")
	env.AddService(service2, "app2")

	time.Sleep(100 * time.Millisecond)

	network, err := types.VirtualNetworkByName(client, "default-domain:testns:private")
	assert.NoError(t, err)
	if err == nil {
		refs, err := network.GetNetworkPolicyRefs()
		assert.NoError(t, err)
		serviceList := make([]string, 0, 2)
		for _, ref := range refs {
			svc, err := serviceNameFromPolicyName(ref.To[len(ref.To)-1])
			if err != nil {
				continue
			}
			serviceList = append(serviceList, svc)
		}
		assert.Equal(t, []string{"foo", "bar"}, serviceList)
	}

	// TODO: update pod
	env.Shutdown()
}

// Issue #75
func TestServiceBeforeNamespace(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := createTestClient()
	controller := NewTestController(kube, client, nil, nil)
	config := controller.config

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "service",
			Namespace: "newns",
			Labels: map[string]string{
				config.NetworkTag: "foo",
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				config.NetworkTag: "app1",
			},
			ClusterIP: "10.254.42.42",
			Type:      api.ServiceTypeClusterIP,
		},
	}

	ns := &api.Namespace{
		ObjectMeta: api.ObjectMeta{
			Name: "newns",
		},
	}
	kube.Pods("newns").(*mocks.KubePodInterface).On("List", mock.Anything).Return(&api.PodList{Items: []api.Pod{}}, nil)
	kube.NamespaceInterface.On("Get", ns.Name).Return(ns, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddService(service)

	time.Sleep(100 * time.Millisecond)
	_, err := types.VirtualNetworkByName(client, "default-domain:newns:service-foo")
	assert.NoError(t, err)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
}

func TestDomainVariable(t *testing.T) {
	kube := mocks.NewKubeClient()

	client := createTestClient()

	controller := NewTestController(kube, client, nil, nil)

	controller.config.DefaultDomain = "test-domain"

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

	glog.Infof("Domain name is %s", controller.config.DefaultDomain)
	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{controller.config.DefaultDomain, "testns"})
	client.Create(netnsProject)

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("List", mock.Anything, mock.Anything).Return(&api.PodList{Items: []api.Pod{*pod1}}, nil)

	shutdown := make(chan struct{})
	go controller.Run(shutdown)

	controller.AddPod(pod1)
	controller.AddService(service)
	time.Sleep(100 * time.Millisecond)

	controller.DeleteService(service)
	controller.DeletePod(pod1)
	controller.DeletePod(pod2)
	time.Sleep(100 * time.Millisecond)

	type shutdownMsg struct {
	}
	shutdown <- shutdownMsg{}
}

func TestGlobalNetworkConnectPodNetworks(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	client := env.client

	config.GlobalNetworks = []string{"default-domain:cluster:external"}

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

	externalNetwork := new(types.VirtualNetwork)
	externalNetwork.SetFQName("project", []string{config.DefaultDomain, "cluster", "external"})
	require.NoError(t, client.Create(externalNetwork))

	env.Start()

	env.AddPod(pod1)
	env.AddPod(pod2)
	env.AddService(service, "server")

	time.Sleep(100 * time.Millisecond)

	policyName := makeGlobalNetworkPolicyName(config, []string{"default-domain", "cluster", "external"})
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	require.NoError(t, err)

	netRefs, err := policy.GetVirtualNetworkBackRefs()
	require.NoError(t, err)
	assert.Len(t, netRefs, 3)
	assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 2)

	env.DeletePod(pod1)
	time.Sleep(100 * time.Millisecond)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	require.NoError(t, err)

	netRefs, err = policy.GetVirtualNetworkBackRefs()
	require.NoError(t, err)
	assert.Len(t, netRefs, 2)
	assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)

	env.DeletePod(pod2)
	env.DeleteService(service, "server")
	time.Sleep(100 * time.Microsecond)

	_, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)

	env.Shutdown()
}

// client pod relies on default NamespaceService in order to connect to server
// since it has no NetworkAccessTag label.
func TestNamespaceServicesDefault(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	client := env.client

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":            "server",
				config.NetworkTag: "server",
			},
		},
	}
	pod2 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz2",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				config.NetworkTag: "client",
			},
		},
	}

	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      "s1",
			Namespace: "testns",
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": "server",
			},
			ClusterIP: "10.254.42.42",
		},
	}

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	require.NoError(t, client.Create(netnsProject))

	env.Start()

	env.AddPod(pod1)
	env.AddPod(pod2)
	env.AddService(service, "server")

	time.Sleep(100 * time.Millisecond)

	policyName := makeServicePolicyName(config, "testns", DefaultServiceNetworkName)
	policy, err := types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	require.NoError(t, err)

	netRefs, err := policy.GetVirtualNetworkBackRefs()
	require.NoError(t, err)
	assert.Len(t, netRefs, 3)
	assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 2)

	env.DeletePod(pod1)
	time.Sleep(100 * time.Millisecond)

	policy, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	require.NoError(t, err)

	netRefs, err = policy.GetVirtualNetworkBackRefs()
	require.NoError(t, err)
	assert.Len(t, netRefs, 2)
	assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 1)

	env.DeletePod(pod2)
	env.DeleteService(service, "server")
	time.Sleep(100 * time.Millisecond)

	_, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)

	env.Shutdown()
}
