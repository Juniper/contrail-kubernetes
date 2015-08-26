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
	"time"

	kubeclient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/client/unversioned/cache"

	"github.com/Juniper/contrail-go-api"
)

const (
	MetadataAnnotationTag = "opencontrail.org/pod-state"
)

// InstanceMetadata contains the information required in the kubernetes minion to
// connect the Pod interface to the network.
type InstanceMetadata struct {
	// Interface uuid
	Uuid string `json:"uuid"`

	// The OpenContrail vrouter verifies the source-mac of the virtual interface.
	MacAddress string `json:"macAddress"`

	// Private IP address
	IpAddress string `json:"ipAddress"`

	// Default gateway (VRouter address)
	Gateway string `json:"gateway"`
}

func NewController(kube *kubeclient.Client, args []string) *Controller {
	controller := new(Controller)
	controller.eventChannel = make(chan notification, 32)
	controller.kube = kube
	config := NewConfig()
	controller.config = config
	config.Parse(args)
	client := contrail.NewClient(config.ApiAddress, config.ApiPort)
	controller.client = client
	controller.allocator = NewAddressAllocator(client, config)
	controller.instanceMgr = NewInstanceManager(client, controller.allocator)
	controller.networkMgr = NewNetworkManager(client, config)
	controller.serviceMgr = NewServiceManager(client, config, controller.networkMgr)
	controller.namespaceMgr = NewNamespaceManager(client)
	controller.consistencyPeriod = time.Duration(1) * time.Minute
	return controller
}

func (c *Controller) SetNamespaceStore(store cache.Store) {
	//	c.NamespaceStore = store
}

func (c *Controller) SetPodStore(store cache.Store) {
	c.podStore = store
}

func (c *Controller) SetReplicationControllerStore(store cache.Store) {
	//	c.RCStore = store
}

func (c *Controller) SetServiceStore(store cache.Store) {
	c.serviceStore = store
}
