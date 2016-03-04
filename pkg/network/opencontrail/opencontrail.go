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
	// MetadataAnnotationTag is the name of the InstanceMetadata annotation on the Pod
	MetadataAnnotationTag = "opencontrail.org/pod-state"

	servicePolicyPrefix = "__svc_"
	networkPolicyPrefix = "__net_"

	// DefaultPodNetworkName is the name for a Pod network, if not specified by the NetworkTag Label.
	DefaultPodNetworkName = "default-network"
	// DefaultServiceNetworkName is the name of the Service network, if not specified by the NetworkTag Label.
	DefaultServiceNetworkName = "default"
)

// InstanceMetadata contains the information required in the kubernetes minion to
// connect the Pod interface to the network.
type InstanceMetadata struct {
	// Interface uuid
	UUID string `json:"uuid"`

	// The OpenContrail vrouter verifies the source-mac of the virtual interface.
	MacAddress string `json:"macAddress"`

	// Private IP address
	IPAddress string `json:"ipAddress"`

	// Default gateway (VRouter address)
	Gateway string `json:"gateway"`
}

// makeSyncController creates a controller that uses a non-buffered (synchronous channel)
// This is used in unit tests to avoid timing problems.
func makeSyncController(kube kubeclient.Interface, config *Config) *Controller {
	controller := new(Controller)
	controller.eventChannel = make(chan notification)
	controller.kube = kube
	controller.config = config
	return controller
}

// NewController allocates a Controller
func NewController(kube *kubeclient.Client, args []string) network.Controller {
	controller := new(Controller)
	controller.eventChannel = make(chan notification, 32)
	controller.kube = kube
	controller.config = NewConfig()
	controller.config.Parse(args)
	return controller
}

func (c *Controller) initComponents(client contrail.ApiClient) {
	c.client = client
	c.allocator = NewAddressAllocator(client, c.config)
	c.instanceMgr = NewInstanceManager(client, c.config, c.allocator)
	c.networkMgr = NewNetworkManager(client, c.config)
	c.serviceMgr = NewServiceManager(client, c.config, c.networkMgr)
	c.namespaceMgr = NewNamespaceManager(client, c.config)
}

// Init initializes the Controller with the configuration.
func (c *Controller) Init(global *network.Config, reader io.Reader) error {
	err := c.config.ReadConfiguration(global, reader)
	if err != nil {
		glog.Error(err)
	}

	glog.Infof("Starting opencontrail plugin")
	glog.Infof("Private Subnet:  %s", c.config.PrivateSubnet)
	glog.Infof("Services Subnet: %s", c.config.ServiceSubnet)
	glog.Infof("Public Subnet:   %s", c.config.PublicSubnet)

	client := contrail.NewClient(c.config.APIAddress, c.config.APIPort)
	c.initComponents(client)
	c.consistencyPeriod = time.Duration(1) * time.Minute

	return nil
}

// SetNamespaceStore is used to pass the pointer of the Namespace cache
func (c *Controller) SetNamespaceStore(store cache.Store) {
	//	c.NamespaceStore = store
}

// SetPodStore is used to pass the pointer of the Pod cache.
func (c *Controller) SetPodStore(store cache.Store) {
	c.podStore = store
}

// SetServiceStore is used to pass the pointer of the Service cache
func (c *Controller) SetServiceStore(store cache.Store) {
	c.serviceStore = store
}

func init() {
	network.Register("opencontrail", NewController)
}
