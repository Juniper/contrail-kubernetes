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
	"k8s.io/kubernetes/pkg/api"
	kubeclient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/version"
)

type KubeClient struct {
	PodInterface     *KubePodInterface
	ServiceInterface *KubeServiceInterface
}

func NewKubeClient() *KubeClient {
	client := new(KubeClient)
	client.PodInterface = new(KubePodInterface)
	client.ServiceInterface = new(KubeServiceInterface)
	return client
}

func (m *KubeClient) Pods(namespace string) kubeclient.PodInterface {
	return m.PodInterface
}
func (m *KubeClient) ReplicationControllers(namespace string) kubeclient.ReplicationControllerInterface {
	return nil
}
func (m *KubeClient) Services(namespace string) kubeclient.ServiceInterface {
	return m.ServiceInterface
}

func (m *KubeClient) Endpoints(namespace string) kubeclient.EndpointsInterface {
	return nil
}

func (m *KubeClient) Daemons(namespace string) kubeclient.DaemonInterface {
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
	return nil
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
func (c *KubeClient) ServerAPIVersions() (*api.APIVersions, error) {
	return nil, nil
}
func (c *KubeClient) ComponentStatuses() kubeclient.ComponentStatusInterface {
	return nil
}
func (c *KubeClient) PodTemplates(namespace string) kubeclient.PodTemplateInterface {
	return nil
}
func (c *KubeClient) ServiceAccounts(namespace string) kubeclient.ServiceAccountsInterface {
	return nil
}
