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

	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod1).Return(pod1, nil)
	kube.Pods("testns").(*mocks.KubePodInterface).On("Update", pod2).Return(pod2, nil)

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

func installPods(env *TestFramework, namespace string, count int) {
	for i := 0; i < count; i++ {
		pod := &api.Pod{
			ObjectMeta: api.ObjectMeta{
				Name:      fmt.Sprintf("pod%02d", i),
				Namespace: namespace,
				UID:       kubetypes.UID(uuid.New()),
				Labels: map[string]string{
					"Name": fmt.Sprintf("pod%02d", i),
				},
			},
		}
		env.AddPod(pod)
	}
}

func TestConsistencyStaleVM(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	client := env.client

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()
	installPods(env, "testns", 3)
	env.SyncBarrier()
	env.Shutdown()

	assert.True(t, env.checker.Check())

	p2 := new(types.Project)
	p2.SetFQName("domain", []string{"default-domain", "p2"})
	assert.NoError(t, client.Create(p2))

	vm := new(types.VirtualMachine)
	vm.SetFQName("project", []string{"default-domain", "p2", "x"})
	assert.NoError(t, client.Create(vm))
	assert.False(t, env.checker.Check())

	assert.NoError(t, client.Delete(vm))
	assert.True(t, env.checker.Check())

	vm = new(types.VirtualMachine)
	vm.SetFQName("project", []string{"default-domain", "testns", "pod03"})
	assert.NoError(t, client.Create(vm))
	assert.False(t, env.checker.Check())
}

func TestConsistencyMissingInterface(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	client := env.client

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()
	installPods(env, "testns", 3)
	env.SyncBarrier()
	env.Shutdown()

	assert.True(t, env.checker.Check())

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

	assert.False(t, env.checker.Check())
}

func TestConsistencyStaleInterface(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	client := env.client

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	env.Start()
	installPods(env, "testns", 3)
	env.SyncBarrier()
	env.Shutdown()

	assert.True(t, env.checker.Check())

	vmi := new(types.VirtualMachineInterface)
	vmi.SetFQName("project", []string{"default-domain", "testns", "pod03"})
	assert.NoError(t, client.Create(vmi))

	assert.False(t, env.checker.Check())
}

func TestConsistencyServiceIp(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	config := env.config
	client := env.client

	netnsProject := new(types.Project)
	netnsProject.SetFQName("domain", []string{"default-domain", "testns"})
	client.Create(netnsProject)

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
				"Name": "pod01",
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
				"Name": "pod02",
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
				"Name": "pod01",
			},
			ClusterIP: "10.254.42.44",
		},
	}

	env.Start()

	installPods(env, "testns", 3)
	env.AddService(service1, "pod01")
	env.AddService(service2, "pod02")
	env.AddService(service3, "pod01")
	env.SyncBarrier()
	env.Shutdown()

	assert.True(t, env.checker.Check())

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
	assert.False(t, env.checker.Check())

	assert.NoError(t, client.Delete(vip))
	assert.True(t, env.checker.Check())

	vip, err = types.FloatingIpByName(client, "default-domain:testns:service-services:service-services:s3")
	assert.NoError(t, err)
	assert.NoError(t, client.Delete(vip))

	assert.False(t, env.checker.Check())
}

func TestConsistencyConnectionsDelete(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")

	client := env.client
	config := env.config
	config.ClusterServices = []string{"kube-system/dns", "kube-system/monitoring"}

	// 2 client pods in network "private"
	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "pod01",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":                  "private",
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
				"Name":                  "private",
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
				"Name":            "provider01",
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
				"Name":            "provider02",
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

	env.Start()

	env.AddPod(pod1)
	env.AddPod(pod2)
	env.AddPod(pod3)
	env.AddPod(pod4)
	env.AddService(service1, "provider01")
	env.AddService(service2, "provider02")

	env.SyncBarrier()
	assert.True(t, env.checker.Check())

	env.DeletePod(pod2)
	env.SyncBarrier()

	assert.False(t, env.checker.Check())
	assert.False(t, env.checker.Check())
	assert.True(t, env.checker.Check())

	config.ClusterServices = []string{"kube-system/dns"}

	assert.False(t, env.checker.Check())
	assert.False(t, env.checker.Check())
	assert.True(t, env.checker.Check())

	env.Shutdown()
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

func TestConsistencyPodUpdateRemovePrev(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	client := env.client
	config := env.config

	pod1 := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "x-1",
			Namespace: "testns",
			UID:       kubetypes.UID(uuid.New()),
			Labels: map[string]string{
				"Name":                  "client",
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
				"Name":                  "client",
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

	env.Start()

	env.AddPod(pod1)
	env.AddService(redService, "red")
	env.AddPod(pod2)
	env.AddPod(pod3)
	env.AddPod(pod4)
	env.AddService(blueService, "blue")
	env.SyncBarrier()

	serviceConnections := getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "red"}, serviceConnections)
	assert.True(t, env.checker.Check())
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
	env.UpdatePod(pod1, nPod1)
	env.SyncBarrier()

	serviceConnections = getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "red", "blue"}, serviceConnections)
	assert.True(t, env.checker.Check(), "red and blue present")

	// Update connections on pod2
	// This will leave a stale connection to network red.
	nPod2 := clonePodAndUpdateAccessTag(pod2, "blue")
	env.UpdatePod(pod2, nPod2)
	env.SyncBarrier()

	serviceConnections = getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "red", "blue"}, serviceConnections)

	assert.False(t, env.checker.Check())

	env.DeleteService(redService, "red")
	env.SyncBarrier()

	// The second pass will delete the connection to network red.
	assert.False(t, env.checker.Check())
	serviceConnections = getNetworkServiceConnections(t, client, config, "testns", "client")
	assert.EqualValues(t, []string{"default", "blue"}, serviceConnections)

	assert.True(t, env.checker.Check())

	env.Shutdown()

	_, err = types.NetworkPolicyByName(client, strings.Join(policyName, ":"))
	assert.Error(t, err)
}

func TestGlobalNetworkConsistencyUpdateNetwork(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")

	config := env.config
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
				"Name":                  "client",
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
				"Name":            "global",
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
	require.NoError(t, env.client.Create(clusterProject))

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	require.NoError(t, env.client.Create(netnsProject))

	env.Start()

	env.AddPod(pod1)
	env.AddPod(pod2)
	env.AddPod(pod3)
	env.AddService(service, "server")
	env.SyncBarrier()

	// This connects the global-network policy with the respective network which is created after
	// the policy.
	assert.False(t, env.checker.Check())
	// It should be ok now.
	assert.True(t, env.checker.Check())

	policyName := makeGlobalNetworkPolicyName(config, []string{"default-domain", "cluster", "global"})
	policy, err := types.NetworkPolicyByName(env.client, strings.Join(policyName, ":"))
	require.NoError(t, err)

	netRefs, err := policy.GetVirtualNetworkBackRefs()
	require.NoError(t, err)
	assert.Len(t, netRefs, 3)
	assert.Len(t, policy.GetNetworkPolicyEntries().PolicyRule, 2)

	env.DeletePod(pod1)
	env.DeletePod(pod2)
	env.DeleteService(service, "server")
	env.SyncBarrier()

	_, err = types.NetworkPolicyByName(env.client, strings.Join(policyName, ":"))
	assert.Error(t, err)

	assert.True(t, env.checker.Check())

	env.Shutdown()
}

func TestGlobalNetworkConsistencyConfigChange(t *testing.T) {
	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")

	config := env.config
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
				"Name":                  "client",
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
				"Name":            "global",
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
	require.NoError(t, env.client.Create(clusterProject))

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	require.NoError(t, env.client.Create(netnsProject))

	env.Start()

	env.AddPod(pod3)
	env.AddPod(pod1)
	env.AddPod(pod2)
	env.AddService(service, "server")
	env.SyncBarrier()

	assert.True(t, env.checker.Check())

	config.GlobalNetworks = []string{}
	for i := 0; i < 2; i++ {
		assert.False(t, env.checker.Check())
	}

	assert.True(t, env.checker.Check())

	policyName := makeGlobalNetworkPolicyName(config, []string{"default-domain", "cluster", "global"})
	_, err := types.NetworkPolicyByName(env.client, strings.Join(policyName, ":"))
	require.Error(t, err)

	env.DeletePod(pod1)
	env.DeletePod(pod2)
	env.DeletePod(pod3)
	env.DeleteService(service, "server")
	env.SyncBarrier()

	env.Shutdown()

	assert.True(t, env.checker.Check())
}
