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
	"io"
	"time"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/client/cache"
	kubeclient "k8s.io/kubernetes/pkg/client/unversioned"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-kubernetes/pkg/network"
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

func NewController(kube *kubeclient.Client, args []string) network.NetworkController {
	controller := new(Controller)
	controller.eventChannel = make(chan notification, 32)
	controller.kube = kube
	controller.config = NewConfig()
	controller.config.Parse(args)
	return controller
}

func (c *Controller) Init(global *network.Config, reader io.Reader) error {
	err := c.config.ReadConfiguration(global, reader)
	if err != nil {
		glog.Error(err)
	}

	glog.Infof("Starting opencontrail plugin")
	glog.Infof("Private Subnet:  %s", c.config.PrivateSubnet)
	glog.Infof("Services Subnet: %s", c.config.ServiceSubnet)
	glog.Infof("Public Subnet:   %s", c.config.PublicSubnet)

	client := contrail.NewClient(c.config.ApiAddress, c.config.ApiPort)
	c.client = client
	c.allocator = NewAddressAllocator(client, c.config)
	c.instanceMgr = NewInstanceManager(client, c.config, c.allocator)
	c.networkMgr = NewNetworkManager(client, c.config)
	c.serviceMgr = NewServiceManager(client, c.config, c.networkMgr)
	c.namespaceMgr = NewNamespaceManager(client, c.config)
	c.consistencyPeriod = time.Duration(1) * time.Minute

	return nil
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

func init() {
	network.Register("opencontrail", NewController)
}
