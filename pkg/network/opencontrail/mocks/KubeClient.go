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

package mocks

import (
	"github.com/emicklei/go-restful/swagger"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	kubeclient "k8s.io/kubernetes/pkg/client/unversioned"
	discovery "k8s.io/kubernetes/pkg/client/typed/discovery"
	"k8s.io/kubernetes/pkg/version"
)

type KubeClient struct {
	podMocks           map[string]*KubePodInterface
	serviceMocks       map[string]*KubeServiceInterface
	NamespaceInterface *KubeNamespaceInterface
}

func NewKubeClient() *KubeClient {
	client := new(KubeClient)
	client.podMocks = make(map[string]*KubePodInterface, 0)
	client.serviceMocks = make(map[string]*KubeServiceInterface, 0)
	client.NamespaceInterface = new(KubeNamespaceInterface)
	return client
}

func (m *KubeClient) Pods(namespace string) kubeclient.PodInterface {
	pods, ok := m.podMocks[namespace]
	if !ok {
		pods = new(KubePodInterface)
		m.podMocks[namespace] = pods
	}
	return pods
}
func (m *KubeClient) ReplicationControllers(namespace string) kubeclient.ReplicationControllerInterface {
	return nil
}
func (m *KubeClient) Services(namespace string) kubeclient.ServiceInterface {
	services, ok := m.serviceMocks[namespace]
	if !ok {
		services = new(KubeServiceInterface)
		m.serviceMocks[namespace] = services
	}
	return services
}

func (m *KubeClient) Endpoints(namespace string) kubeclient.EndpointsInterface {
	return nil
}

func (m *KubeClient) Events(namespace string) kubeclient.EventInterface {
	return nil
}
func (c *KubeClient) Nodes() kubeclient.NodeInterface {
	return nil
}
func (c *KubeClient) LimitRanges(namespace string) kubeclient.LimitRangeInterface {
	return nil
}

func (c *KubeClient) ResourceQuotas(namespace string) kubeclient.ResourceQuotaInterface {
	return nil
}

func (c *KubeClient) Secrets(namespace string) kubeclient.SecretsInterface {
	return nil
}

func (c *KubeClient) Namespaces() kubeclient.NamespaceInterface {
	return c.NamespaceInterface
}

func (c *KubeClient) PersistentVolumes() kubeclient.PersistentVolumeInterface {
	return nil
}

func (c *KubeClient) PersistentVolumeClaims(namespace string) kubeclient.PersistentVolumeClaimInterface {
	return nil
}
func (c *KubeClient) ServerVersion() (*version.Info, error) {
	return nil, nil
}
func (c *KubeClient) ServerAPIVersions() (*unversioned.APIVersions, error) {
	return nil, nil
}
func (c *KubeClient) ComponentStatuses() kubeclient.ComponentStatusInterface {
	return nil
}
func (c *KubeClient) ConfigMaps(namespace string) kubeclient.ConfigMapsInterface {
	return nil
}
func (c *KubeClient) PodTemplates(namespace string) kubeclient.PodTemplateInterface {
	return nil
}
func (c *KubeClient) ServiceAccounts(namespace string) kubeclient.ServiceAccountsInterface {
	return nil
}

func (c *KubeClient) ValidateComponents() (*api.ComponentStatusList, error) {
	return nil, nil
}

func (c *KubeClient) SwaggerSchema(version string) (*swagger.ApiDeclaration, error) {
	return nil, nil
}

func (c *KubeClient) Extensions() kubeclient.ExtensionsInterface {
	return nil
}

func (c *KubeClient) Autoscaling() kubeclient.AutoscalingInterface {
	return nil
}

func (c *KubeClient) Batch() kubeclient.BatchInterface {
	return nil
}

func (c *KubeClient) Discovery() discovery.DiscoveryInterface {
	return nil
}

func (m *KubeServiceInterface) UpdateStatus(srv *api.Service) (*api.Service, error) {
	ret := m.Called(srv)
	var r0 *api.Service
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Service)
	}
	r1 := ret.Error(1)
	return r0, r1
}
