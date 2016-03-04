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
	"math/rand"
	"strings"
	"testing"

	"github.com/golang/glog"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"

	"k8s.io/kubernetes/pkg/api"
	kubetypes "k8s.io/kubernetes/pkg/types"
)

type tierConfig struct {
	Name         string
	MaxInstances int
	Connections  []string
	Service      api.ServiceType
}

var (
	testProjects = []string{"cluster", "appA", "appB"}
	testTiers    = map[string][]tierConfig{
		testProjects[0]: []tierConfig{
			tierConfig{Name: "default", MaxInstances: 2},
			tierConfig{Name: "log", MaxInstances: 2, Service: api.ServiceTypeClusterIP},
		},
		testProjects[1]: []tierConfig{
			tierConfig{Name: "web", MaxInstances: 5, Connections: []string{"cache", "db"}, Service: api.ServiceTypeLoadBalancer},
			tierConfig{Name: "cache", MaxInstances: 3, Service: api.ServiceTypeClusterIP},
			tierConfig{Name: "db", MaxInstances: 2, Service: api.ServiceTypeClusterIP},
		},
		testProjects[2]: []tierConfig{
			tierConfig{Name: "web", MaxInstances: 1, Connections: []string{"monitor", "db", "aux"}, Service: api.ServiceTypeLoadBalancer},
			tierConfig{Name: "monitor", MaxInstances: 1, Service: api.ServiceTypeClusterIP},
			tierConfig{Name: "db", MaxInstances: 2, Connections: []string{"monitor"}, Service: api.ServiceTypeClusterIP},
			tierConfig{Name: "aux", MaxInstances: 3, Connections: []string{"monitor"}, Service: api.ServiceTypeClusterIP},
		},
	}
)

func appendUnique(array []string, element string) []string {
	for _, v := range array {
		if v == element {
			return array
		}
	}
	return append(array, element)
}

func stringSliceRemove(array []string, element string) []string {
	for i, v := range array {
		if v == element {
			return append(array[:i], array[i+1:]...)
		}
	}
	return array
}

type transform interface {
	init(env *TestFramework) bool
	exec(env *TestFramework)
}

func selectTier() (string, *tierConfig) {
	coin := rand.Int()
	// select project
	projectNum := coin % len(testProjects)
	projectName := testProjects[projectNum]
	coin = coin - projectNum

	// select tier
	tierList := testTiers[projectName]
	tierNum := coin % len(tierList)
	return projectName, &tierList[tierNum]
}

type addPodTransform struct {
	pod *api.Pod
}

func (t *addPodTransform) init(env *TestFramework) bool {
	projectName, config := selectTier()

	data := env.GetGroupState(projectName, config.Name)
	if len(data.Pods) == config.MaxInstances {
		return false
	}
	objectID := uuid.New()
	pod := api.Pod{
		ObjectMeta: api.ObjectMeta{
			UID:       kubetypes.UID(objectID),
			Name:      config.Name + "-" + objectID[0:8],
			Namespace: projectName,
			Labels: map[string]string{
				"Name":                config.Name,
				env.config.NetworkTag: config.Name,
			},
		},
	}
	if config.Connections != nil {
		pod.ObjectMeta.Labels[env.config.NetworkAccessTag] = config.Connections[rand.Intn(len(config.Connections))]
	}
	t.pod = &pod
	return true
}

func (t *addPodTransform) exec(env *TestFramework) {
	glog.Infof("add Pod %s/%s", t.pod.Namespace, t.pod.Name)
	env.AddPod(t.pod)
}

type deletePodTransform struct {
	pod *api.Pod
}

func (t *deletePodTransform) init(env *TestFramework) bool {
	projectName, config := selectTier()

	data := env.GetGroupState(projectName, config.Name)
	if len(data.Pods) == 0 {
		return false
	}
	t.pod = data.Pods[rand.Intn(len(data.Pods))]
	return true
}

func (t *deletePodTransform) exec(env *TestFramework) {
	glog.Infof("delete Pod %s/%s", t.pod.Namespace, t.pod.Name)
	env.DeletePod(t.pod)
}

type addServiceTransform struct {
	service *api.Service
}

func (t *addServiceTransform) init(env *TestFramework) bool {
	projectName, config := selectTier()

	if config.Service == "" {
		return false
	}
	state := env.GetGroupState(projectName, config.Name)
	if len(state.Services) > 0 {
		return false
	}
	service := &api.Service{
		ObjectMeta: api.ObjectMeta{
			Name:      config.Name,
			Namespace: projectName,
			Labels: map[string]string{
				env.config.NetworkTag: config.Name,
			},
		},
		Spec: api.ServiceSpec{
			Selector: map[string]string{
				"Name": config.Name,
			},
			ClusterIP: env.AllocateClusterIP(config.Name),
			Type:      config.Service,
		},
	}
	t.service = service
	return true
}

func (t *addServiceTransform) exec(env *TestFramework) {
	glog.Infof("add service %s/%s", t.service.Namespace, t.service.Name)
	env.AddService(t.service, t.service.Name)
}

type deleteServiceTransform struct {
	service *api.Service
}

func (t *deleteServiceTransform) init(env *TestFramework) bool {
	projectName, config := selectTier()
	state := env.GetGroupState(projectName, config.Name)
	if len(state.Services) == 0 {
		return false
	}
	t.service = state.Services[0]
	return true
}

func (t *deleteServiceTransform) exec(env *TestFramework) {
	glog.Infof("delete service %s/%s", t.service.Namespace, t.service.Name)
	env.DeleteService(t.service, t.service.Name)
}

type updateGlobalNetworkConfig struct {
}

func (t *updateGlobalNetworkConfig) init(env *TestFramework) bool {
	globalNetworkName := strings.Join([]string{env.config.DefaultDomain, "cluster", "default"}, ":")
	coin := rand.Intn(8)
	switch coin {
	case 0:
		// Add global service
		env.config.ClusterServices = appendUnique(env.config.ClusterServices, "cluster/log")
		break
	case 1:
		// Delete global service
		env.config.ClusterServices = stringSliceRemove(env.config.ClusterServices, "cluster/log")
		break
	case 2:
		// Add global network
		env.config.GlobalNetworks = appendUnique(env.config.GlobalNetworks, globalNetworkName)
		break
	case 3:
		// Delete global network
		env.config.GlobalNetworks = stringSliceRemove(env.config.GlobalNetworks, globalNetworkName)
		break
	default:
		return false
	}
	return true
}

func (t *updateGlobalNetworkConfig) exec(env *TestFramework) {
	glog.Infof("update global network config")
}

func TestRandom(t *testing.T) {
	transforms := []transform{
		&addPodTransform{},
		&deletePodTransform{},
		&addServiceTransform{},
		&deleteServiceTransform{},
	}

	env := new(TestFramework)
	env.SetUp("192.0.2.0/24")
	env.Start()

	for i := 0; i < 128; i++ {
		tf := transforms[rand.Int()%len(transforms)]
		doExec := tf.init(env)
		if !doExec {
			continue
		}
		tf.exec(env)
		env.SyncBarrier()
		check := env.checker.Check()
		if !check {
			env.checker.Check()
			assert.True(t, env.checker.Check(), "iteration %d", i)
		}
	}

	env.Shutdown()
}

// TODO(prm): repeat test without public network configuration.
