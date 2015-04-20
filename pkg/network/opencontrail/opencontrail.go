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
	"strings"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	kubeclient "github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/golang/glog"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/config"
	"github.com/Juniper/contrail-go-api/types"
)

// The OpenContrail controller maps kubernetes objects into networking
// properties such that:
// - Each Pod/Replication controller is assigned a unique network
// - desiredState.labels.uses connects virtual networks
// - Services allocate floating-ip addresses and/or LBaaS.

type Controller struct {
	Kube   *kubeclient.Client
	Client *contrail.Client
}

// TODO(prm): use configuration file to modify parameters
const (
	ApiAddress     = "localhost"
	ApiPort        = 8082
	DefaultProject = "default-domain:default-project"
	PublicNetwork  = "default-domain:default-project:Public"
	PublicSubnet   = "192.168.254.0/24"
	PrivateSubnet  = "10.0.0.0/8"

	AddressAllocationNetwork = "default-domain:default-project:addr-alloc"
)

func NewController(kube *kubeclient.Client) *Controller {
	controller := new(Controller)
	controller.Kube = kube
	controller.Client = contrail.NewClient(ApiAddress, ApiPort)
	controller.initializeNetworks()
	return controller
}

func (c *Controller) initializePublicNetwork() {
	_, err := c.Client.FindByName("virtual-network", PublicNetwork)
	if err != nil {
		fqn := strings.Split(PublicNetwork, ":")
		parent := strings.Join(fqn[0:len(fqn)-1], ":")
		projectId, err := c.Client.UuidByName("project", parent)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		_, err = config.CreateNetworkWithSubnet(
			c.Client, projectId, fqn[len(fqn)-1], PublicSubnet)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		glog.Infof("Created network %s", PublicNetwork)

	}
	// TODO(prm): Ensure that the subnet is as specified.
}

// Temporary workaround for address allocation
func (c *Controller) initializeAddrAllocNetwork() {
	_, err := c.Client.FindByName("virtual-network",
		AddressAllocationNetwork)
	if err != nil {
		fqn := strings.Split(AddressAllocationNetwork, ":")
		parent := strings.Join(fqn[0:len(fqn)-1], ":")
		projectId, err := c.Client.UuidByName("project", parent)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		_, err = config.CreateNetworkWithSubnet(
			c.Client, projectId, fqn[len(fqn)-1], PrivateSubnet)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		glog.Infof("Created network %s", AddressAllocationNetwork)
	}

}

func (c *Controller) initializeNetworks() {
	c.initializePublicNetwork()
	c.initializeAddrAllocNetwork()
}

func (c *Controller) allocateIpAddress(uid string) string {
	network, err := c.Client.FindByName(
		"virtual-network", AddressAllocationNetwork)
	if err != nil {
		glog.Fatalf("GET %s: %v", AddressAllocationNetwork, err)
	}
	ipObj := new(types.InstanceIp)
	ipObj.SetName(uid)
	ipObj.AddVirtualNetwork(network.(*types.VirtualNetwork))
	err = c.Client.Create(ipObj)
	if err != nil {
		glog.Fatalf("Create InstanceIp %s: %v", uid, err)
	}
	return ipObj.GetInstanceIpAddress()
}

func (c *Controller) releaseIpAddress(uid string) {
	objid, err := c.Client.UuidByName("instance-ip", uid)
	if err != nil {
		err = c.Client.DeleteByUuid("instance-ip", objid)
		if err != nil {
			glog.Warningf("Delete instance-ip: %v", err)
		}
	}
}

// assume that labels["name"] names the network
func (c *Controller) getPodNetwork(pod *api.Pod) *types.VirtualNetwork {
	name, ok := pod.Labels["name"]
	if !ok {
		name = "default-network"
	}
	fqn := strings.Split(DefaultProject, ":")
	fqn = append(fqn, name)
	network, err := c.Client.FindByName("virtual-network", PublicNetwork)
	if err != nil {
		projectId, err := c.Client.UuidByName("project", DefaultProject)
		if err != nil {
			glog.Infof("GET %s: %v", DefaultProject, err)
			return nil
		}
		uid, err := config.CreateNetworkWithSubnet(
			c.Client, projectId, name, PrivateSubnet)
		if err != nil {
			glog.Infof("Create %s: %v", name, err)
			return nil
		}
		network, err = c.Client.FindByUuid("virtual-network", uid)
		if err != nil {
			glog.Infof("GET %s: %v", name, err)
			return nil
		}

	}
	return network.(*types.VirtualNetwork)
}

func (c *Controller) locateInstance(pod *api.Pod, project *types.Project) *types.VirtualMachine {
	obj, err := c.Client.FindByUuid(
		"virtual-machine", string(pod.ObjectMeta.UID))
	if err == nil {
		return obj.(*types.VirtualMachine)
	}

	instance := new(types.VirtualMachine)
	instance.SetName(pod.ObjectMeta.Name)
	instance.SetParent(project)
	instance.SetUuid(string(pod.ObjectMeta.UID))
	err = c.Client.Create(instance)
	if err != nil {
		glog.Errorf("Create %s: %v", pod.ObjectMeta.Name)
		return nil
	}
	return instance
}

func (c *Controller) locateInterface(
	pod *api.Pod, project *types.Project, network *types.VirtualNetwork) *types.VirtualMachineInterface {
	fqn := append(project.GetFQName(), pod.ObjectMeta.Name)
	obj, err := c.Client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))

	if err == nil {
		nic := obj.(*types.VirtualMachineInterface)
		// TODO(prm): ensure network is as expected, else update.
		return nic
	}

	nic := new(types.VirtualMachineInterface)
	nic.SetName(pod.ObjectMeta.Name)
	nic.SetParent(project)
	if network != nil {
		nic.AddVirtualNetwork(network)
	}
	err = c.Client.Create(nic)
	if err != nil {
		glog.Errorf("Create interface %s: %v", pod.ObjectMeta.Name, err)
		return nil
	}
	return nic
}

func (c *Controller) locateInstanceIp(
	pod *api.Pod, network *types.VirtualNetwork,
	nic *types.VirtualMachineInterface) *types.InstanceIp {

	obj, err := c.Client.FindByName("instance-ip", pod.ObjectMeta.Name)
	if err == nil {
		// TODO(prm): ensure that attributes are as expected
		return obj.(*types.InstanceIp)
	}

	address := c.allocateIpAddress(string(pod.ObjectMeta.UID))
	// Create InstanceIp
	ipObj := new(types.InstanceIp)
	ipObj.SetName(pod.ObjectMeta.Name)
	ipObj.AddVirtualNetwork(network)
	ipObj.AddVirtualMachineInterface(nic)
	ipObj.SetInstanceIpAddress(address)
	err = c.Client.Create(ipObj)
	if err != nil {
		glog.Errorf("Create instance-ip %s: %v", pod.ObjectMeta.Name)
		return nil
	}
	return ipObj
}

// virtual-machine object (metadata.uid)
// virtual-machine-interface
//	- allocate IP address
//	- attach to network
//
// a) RC to Pod map.
// b) metadata.generateName
//
func (c *Controller) AddPod(pod *api.Pod) {
	// TODO(prm): use namespace for project
	obj, err := c.Client.FindByName("project", DefaultProject)
	if err != nil {
		glog.Fatalf("%s: %v", DefaultProject, err)
	}

	project := obj.(*types.Project)
	c.locateInstance(pod, project)
	network := c.getPodNetwork(pod)
	nic := c.locateInterface(pod, project, network)

	// Modify the POD object such that its Annotations['vmi'] is updated with
	// the UUID of the nic
	pod.Annotations["vmi"] = nic.GetUuid()
	c.Kube.Pods(pod.Namespace).Update(pod)

	if network != nil {
		c.locateInstanceIp(pod, network, nic)
	}

	// If the Pod has been created by a ReplicationController (GenerateName
	// is set) then defer the handling of the "uses" tag to the controller.
	if pod.GenerateName == "" {
		policyTag, ok := pod.Labels["uses"]
		if ok {
			c.networkAccess(network, policyTag)
		}
	}
}

func (c *Controller) UpdatePod(oldObj, newObj *api.Pod) {
}

// DeletePod
func (c *Controller) DeletePod(pod *api.Pod) {
	// TODO(prm): use namespace for project
	obj, err := c.Client.FindByName("project", DefaultProject)
	if err != nil {
		glog.Fatalf("%s: %v", DefaultProject, err)
	}
	project := obj.(*types.Project)

	fqn := append(project.GetFQName(), pod.ObjectMeta.Name)
	fqname := strings.Join(fqn, ":")
	uid, err := c.Client.UuidByName("instance-ip", fqname)
	if err != nil {
		err = c.Client.DeleteByUuid("instance-ip", uid)
		if err != nil {
			glog.Warningf("Delete instance-ip: %v", err)
		}
	}

	c.releaseIpAddress(string(pod.ObjectMeta.UID))

	uid, err = c.Client.UuidByName(
		"virtual-machine-interface", fqname)
	if err != nil {
		err = c.Client.DeleteByUuid("virtual-machine-interface", uid)
		if err != nil {
			glog.Warningf("Delete vmi: %v", err)
		}
	}

	err = c.Client.DeleteByUuid(
		"virtual-machine", string(pod.ObjectMeta.UID))
	if err != nil {
		glog.Warningf("Delete instance: %v", err)
	}

	// TODO(prm): cleanup the network if there are no more interfaces
	// associated with it.
}

func (c *Controller) AddNamespace(obj *api.Namespace) {
}

func (c *Controller) UpdateNamespace(oldObj, newObj *api.Namespace) {
}

func (c *Controller) DeleteNamespace(obj *api.Namespace) {
}

func (c *Controller) networkAccess(
	network *types.VirtualNetwork, policyTag string) {
}

func (c *Controller) AddReplicationController(rc *api.ReplicationController) {
	// policyTag, ok := rc.Labels["uses"]
	// if ok {
	// 	c.networkAccess(network, policyTag)
	// }
}

func (c *Controller) UpdateReplicationController(
	oldObj, newObj *api.ReplicationController) {
}

func (c *Controller) DeleteReplicationController(
	rc *api.ReplicationController) {
	// TODO: delete policies.
}

// Services can specify "publicIPs", these are mapped to floating-ip
// addresses. By default a service implies a mapping from a service address
// to the backends.
func (c *Controller) AddService(service *api.Service) {
}

func (c *Controller) UpdateService(oldObj, newObj *api.Service) {
}

func (c *Controller) DeleteService(service *api.Service) {
}
