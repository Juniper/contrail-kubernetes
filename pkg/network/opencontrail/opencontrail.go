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
	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"

	"github.com/Juniper/contrail-go-api"
)

// The OpenContrail controller maps kubernetes objects into networking
// properties such that:
// - Each Pod/Replication controller is assigned a unique network
// - desiredState.labels.uses connects virtual networks
// - Services allocate floating-ip addresses and/or LBaaS.

type Controller struct {
	Client *contrail.Client
}

// TODO(prm): use configuration file to modify parameters
const (
	ApiAddress = "localhost"
	ApiPort = 8082
	DefaultProject = "default-project"
	PublicNetwork = "default-domain:default-project:Public"
	PrivateSubnet = "10.0.0.0/8"
	
	AddressAllocationNetwork = "default-domain:default-project:addr-alloc"
)

func NewController() *Controller {
	controller := new(Controller)
	controller.Client = contrail.NewClient(ApiAddress, ApiPort)
	return controller
}

func (c *Controller) AddPod(obj *api.Pod) {
}

func (c *Controller) UpdatePod(oldObj, newObj *api.Pod) {
}

func (c *Controller) DeletePod(obj *api.Pod) {
}

func (c *Controller) AddNamespace(obj *api.Namespace) {
}

func (c *Controller) UpdateNamespace(oldObj, newObj *api.Namespace) {
}

func (c *Controller) DeleteNamespace(obj *api.Namespace) {
}

func (c *Controller) AddReplicationController(obj *api.ReplicationController) {
}

func (c *Controller) UpdateReplicationController(
	oldObj, newObj *api.ReplicationController) {
}

func (c *Controller) DeleteReplicationController(
	obj *api.ReplicationController) {
}

func (c *Controller) AddService(obj *api.Service) {
}

func (c *Controller) UpdateService(oldObj, newObj *api.Service) {
}

func (c *Controller) DeleteService(obj *api.Service) {
}
