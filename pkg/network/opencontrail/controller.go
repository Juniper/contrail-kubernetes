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
	"fmt"
	"strings"

	"github.com/golang/glog"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	kubeclient "github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/runtime"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

// The OpenContrail controller maps kubernetes objects into networking
// properties such that:
// - Each Pod/Replication controller is assigned a unique network
// - Labels are used to connectsvirtual networks
// - Services allocate floating-ip addresses.

type Controller struct {
	kube kubeclient.Interface

	client contrail.ApiClient
	config *Config

	eventChannel chan notification

	instanceMgr  *InstanceManager
	networkMgr   NetworkManager
	serviceMgr   *ServiceManager
	namespaceMgr *NamespaceManager
	allocator    AddressAllocator
}

type eventType string

const (
	evAddNamespace    eventType = "AddNamespace"
	evDeleteNamespace eventType = "DeleteNamespace"
	evUpdateNamespace eventType = "UpdateNamespace"
	evAddPod          eventType = "AddPod"
	evDeletePod       eventType = "DeletePod"
	evUpdatePod       eventType = "UpdatePod"
	evAddService      eventType = "AddService"
	evDeleteService   eventType = "DeleteService"
	evUpdateService   eventType = "UpdateService"
)

type notification struct {
	event  eventType
	object runtime.Object
}

const (
	ServiceNetworkFmt = "service-%s"
)

func (c *Controller) Run(shutdown chan struct{}) {
	for {
		select {
		case event := <-c.eventChannel:
			switch event.event {
			case evAddPod:
				c.updatePod(event.object.(*api.Pod))
			case evUpdatePod:
				c.updatePod(event.object.(*api.Pod))
			case evDeletePod:
				c.deletePod(event.object.(*api.Pod))
			case evAddService:
				c.addService(event.object.(*api.Service))
			case evDeleteService:
				c.deleteService(event.object.(*api.Service))
			case evAddNamespace:
				c.addNamespace(event.object.(*api.Namespace))
			case evDeleteNamespace:
				c.deleteNamespace(event.object.(*api.Namespace))
			}
		case <-shutdown:
			return
		}
	}
}

func updateElement(m map[string]string, tag, value string) bool {
	current, ok := m[tag]
	if ok && current == value {
		return false
	}
	m[tag] = value
	return true
}

func (c *Controller) updateInstanceMetadata(
	pod *api.Pod, nic *types.VirtualMachineInterface, address, gateway string) {
	doUpdate := false

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
		doUpdate = true
	}

	if updateElement(pod.Annotations, "nic_uuid", nic.GetUuid()) {
		doUpdate = true
	}
	if updateElement(pod.Annotations, "mac_address", nic.GetVirtualMachineInterfaceMacAddresses().MacAddress[0]) {
		doUpdate = true
	}
	if updateElement(pod.Annotations, "ip_address", address) {
		doUpdate = true
	}
	if updateElement(pod.Annotations, "gateway", gateway) {
		doUpdate = true
	}
	if !doUpdate {
		return
	}

	_, err := c.kube.Pods(pod.Namespace).Update(pod)
	if err != nil {
		// Update will return an error if the pod object that we are
		// working with is stale.
		glog.Infof("Pod Update %s: %v", pod.Name, err)
	}
}

// Retrieve the private network for this Pod.
func (c *Controller) getPodNetwork(pod *api.Pod) *types.VirtualNetwork {
	name, ok := pod.Labels[c.config.NetworkTag]
	if !ok {
		name = "default-network"
	}
	return c.networkMgr.LocateNetwork(pod.Namespace, name, c.config.PrivateSubnet)
}

func (c *Controller) serviceNetworkName(labels map[string]string) string {
	name, ok := labels[c.config.NetworkTag]
	if !ok {
		return "services"
	}

	return fmt.Sprintf(ServiceNetworkFmt, name)
}

func (c *Controller) locateServiceNetwork(service *api.Service) *types.VirtualNetwork {
	name := c.serviceNetworkName(service.Labels)
	network := c.networkMgr.LocateNetwork(service.Namespace, name, c.config.ServiceSubnet)
	c.networkMgr.LocateFloatingIpPool(network, name, c.config.ServiceSubnet)
	return network
}

func (c *Controller) ensureNamespace(namespaceName string) {
	project := c.namespaceMgr.LookupNamespace(namespaceName)
	if project != nil {
		return
	}
	namespace, err := c.kube.Namespaces().Get(namespaceName)
	if err != nil {
		glog.Errorf("Get namespace %s: %v", namespaceName, err)
		return
	}
	project = c.namespaceMgr.LocateNamespace(namespace.Name, string(namespace.ObjectMeta.UID))
}

func (c *Controller) updatePod(pod *api.Pod) {
	glog.Infof("Pod %s", pod.Name)

	c.ensureNamespace(pod.Namespace)
	instance := c.instanceMgr.LocateInstance(pod.Namespace, pod.Name, string(pod.ObjectMeta.UID))

	network := c.getPodNetwork(pod)
	if network == nil {
		return
	}
	nic := c.instanceMgr.LocateInterface(network, instance)
	if nic == nil {
		return
	}
	address := c.instanceMgr.LocateInstanceIp(network, string(pod.ObjectMeta.UID), nic)
	if address == nil {
		return
	}
	gateway, err := c.networkMgr.GetGatewayAddress(network)
	if err != nil {
		return
	}
	c.updateInstanceMetadata(pod, nic, address.GetInstanceIpAddress(), gateway)

	policyTag, ok := pod.Labels[c.config.NetworkAccessTag]
	if ok {
		var policyName string
		if pod.GenerateName == "" {
			policyName = pod.Name
		} else {
			policyName = strings.TrimRight(pod.GenerateName, "-")
		}
		serviceName := fmt.Sprintf(ServiceNetworkFmt, policyTag)
		c.serviceMgr.NetworkAccess(network, policyName, serviceName)
	}
}

// DeletePod
func (c *Controller) deletePod(pod *api.Pod) {
	glog.Infof("Delete Pod %s", pod.Name)

	c.instanceMgr.ReleaseInstanceIp(pod.Namespace, pod.Name, string(pod.ObjectMeta.UID))
	c.instanceMgr.ReleaseInterface(pod.Namespace, pod.Name)
	c.instanceMgr.DeleteInstance(string(pod.ObjectMeta.UID))
	// TODO(prm): cleanup the network if there are no more interfaces
	// associated with it.
}

// Services can specify "publicIPs", these are mapped to floating-ip
// addresses. By default a service implies a mapping from a service address
// to the backends.
func (c *Controller) addService(service *api.Service) {
	glog.Infof("Add Service %s", service.Name)

	pods, err := c.kube.Pods(service.Namespace).List(
		labels.Set(service.Spec.Selector).AsSelector())
	if err != nil {
		glog.Errorf("List pods by service %s: %v", service.Name, err)
		return
	}

	if len(pods.Items) == 0 {
		return
	}

	var serviceIp *types.FloatingIp = nil
	var serviceNetwork *types.VirtualNetwork = nil
	// Allocate this IP address on the service network.
	if service.Spec.PortalIP != "" {
		serviceNetwork = c.locateServiceNetwork(service)
		if serviceNetwork != nil {
			serviceIp = c.networkMgr.LocateFloatingIp(
				serviceNetwork.GetName(), service.Name, service.Spec.PortalIP)
		}
	}

	var publicIp *types.FloatingIp = nil
	if service.Spec.PublicIPs != nil {
		// Allocate a floating-ip from the public pool.
		publicIp = c.networkMgr.LocateFloatingIp(
			c.config.PublicNetwork, service.Name, service.Spec.PublicIPs[0])
	}

	if serviceIp == nil && publicIp == nil {
		return
	}

	for _, pod := range pods.Items {
		if serviceIp != nil {
			// Connect serviceIp to VMI.
			c.instanceMgr.AttachFloatingIp(pod.Name, pod.Namespace, serviceIp)
		}
		if publicIp != nil {
			c.instanceMgr.AttachFloatingIp(pod.Name, pod.Namespace, publicIp)
		}
	}

	// There may be a policy implied in the service definition.
	// networkName, ok := service.Labels["name"]
	// if !ok {
	// 	networkName = "default-network"
	// }
	// policyTag, ok := service.Labels["uses"]
	// if ok {
	// 	network := c.lookupNetwork(DefaultProject, networkName)
	// 	c.networkAccess(network, service.Name, policyTag)
	// }
}

func (c *Controller) deleteService(service *api.Service) {
	networkName := c.serviceNetworkName(service.Labels)
	network := c.networkMgr.LookupNetwork(service.Namespace, networkName)
	if network == nil {
		return
	}

	c.networkMgr.DeleteFloatingIpPool(network, networkName, true)
	c.networkMgr.DeleteNetwork(network)
}

func (c *Controller) addNamespace(namespace *api.Namespace) {
	c.namespaceMgr.LocateNamespace(namespace.Name, string(namespace.ObjectMeta.UID))
}

func (c *Controller) deleteNamespace(namespace *api.Namespace) {
	c.namespaceMgr.DeleteNamespace(namespace.Name)
}
