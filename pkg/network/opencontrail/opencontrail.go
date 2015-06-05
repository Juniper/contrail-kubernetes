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
	kubeclient "github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"

	"github.com/Juniper/contrail-go-api"
)

// InstanceMetadata contains the information required in the kubernetes minion to
// connect the Pod interface to the network.
type InstanceMetadata struct {
	// Interface uuid
	Uuid string

	// The OpenContrail vrouter verifies the source-mac of the virtual interface.
	MacAddress string

	// Private IP address
	IpAddress string

	// Default gateway (VRouter address)
	Gateway string
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
	return controller
}

func (c *Controller) SetNamespaceStore(store cache.Store) {
	//	c.NamespaceStore = store
}

func (c *Controller) SetPodStore(store cache.Store) {
	//	c.PodStore = store
}

func (c *Controller) SetReplicationControllerStore(store cache.Store) {
	//	c.RCStore = store
}

func (c *Controller) SetServiceStore(store cache.Store) {
	c.serviceStore = store
}
