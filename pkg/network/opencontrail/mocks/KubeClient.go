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
	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/version"
)

type KubeClient struct {
	PodInterface *KubePodInterface
}

func NewKubeClient() *KubeClient {
	client := new(KubeClient)
	client.PodInterface = new(KubePodInterface)
	return client
}

func (m *KubeClient) Pods(namespace string) client.PodInterface {
	return m.PodInterface
}
func (m *KubeClient) ReplicationControllers(namespace string) client.ReplicationControllerInterface {
	return nil
}
func (m *KubeClient) Services(namespace string) client.ServiceInterface {
	return nil
}

func (m *KubeClient) Endpoints(namespace string) client.EndpointsInterface {
	return nil
}

func (m *KubeClient) Events(namespace string) client.EventInterface {
	return nil
}
func (c *KubeClient) Nodes() client.NodeInterface {
	return nil
}
func (c *KubeClient) LimitRanges(namespace string) client.LimitRangeInterface {
	return nil
}

func (c *KubeClient) ResourceQuotas(namespace string) client.ResourceQuotaInterface {
	return nil
}

func (c *KubeClient) Secrets(namespace string) client.SecretsInterface {
	return nil
}

func (c *KubeClient) Namespaces() client.NamespaceInterface {
	return nil
}

func (c *KubeClient) PersistentVolumes() client.PersistentVolumeInterface {
	return nil
}

func (c *KubeClient) PersistentVolumeClaims(namespace string) client.PersistentVolumeClaimInterface {
	return nil
}
func (c *KubeClient) ServerVersion() (*version.Info, error) {
	return nil, nil
}
func (c *KubeClient) ServerAPIVersions() (*api.APIVersions, error) {
	return nil, nil
}
