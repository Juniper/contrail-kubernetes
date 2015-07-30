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
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/golang/glog"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	kubeclient "github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
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

	podStore     cache.Store
	serviceStore cache.Store

	instanceMgr  *InstanceManager
	networkMgr   NetworkManager
	serviceMgr   ServiceManager
	namespaceMgr *NamespaceManager
	allocator    AddressAllocator

	consistencyPeriod time.Duration
	consistencyWorker ConsistencyChecker
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

func (c *Controller) Run(shutdown chan struct{}) {
	var timerChan <-chan time.Time

	if c.consistencyPeriod != 0 {
		timerChan = time.NewTicker(c.consistencyPeriod * time.Second).C
		c.consistencyWorker = NewConsistencyChecker(c.client, c.podStore, c.serviceStore)
	}

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
			case evUpdateService:
				c.updateService(event.object.(*api.Service))
			case evDeleteService:
				c.deleteService(event.object.(*api.Service))
			case evAddNamespace:
				c.addNamespace(event.object.(*api.Namespace))
			case evDeleteNamespace:
				c.deleteNamespace(event.object.(*api.Namespace))
			}
		case <-timerChan:
			c.consistencyWorker.Check()
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
	var mac_address string
	addressArr := nic.GetVirtualMachineInterfaceMacAddresses()
	if len(addressArr.MacAddress) > 0 {
		mac_address = addressArr.MacAddress[0]
	} else {
		glog.Errorf("interface %s: no mac-addresses", nic.GetName())
	}
	if updateElement(pod.Annotations, "mac_address", mac_address) {
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
	network, err := c.networkMgr.LocateNetwork(pod.Namespace, name, c.config.PrivateSubnet)
	if err != nil {
		return nil
	}
	return network
}

func (c *Controller) serviceName(labels map[string]string) string {
	name, ok := labels[c.config.NetworkTag]
	if !ok {
		return "default"
	}

	return name
}

// Include the namespace in the resource name so one can deploy the same service in different namespaces.
func publicIpResourceName(service *api.Service) string {
	return fmt.Sprintf("%s_%s", service.Namespace, service.Name)
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

func (c *Controller) updatePodServiceIp(service *api.Service, pod *api.Pod) {
	if service.Spec.ClusterIP == "" {
		return
	}

	serviceName := c.serviceName(service.Labels)
	serviceNetwork, err := c.serviceMgr.LocateServiceNetwork(service.Namespace, serviceName)
	if err != nil {
		return
	}
	serviceIp, err := c.networkMgr.LocateFloatingIp(serviceNetwork, service.Name, service.Spec.ClusterIP)
	if err != nil {
		return
	}
	c.instanceMgr.AttachFloatingIp(pod.Name, pod.Namespace, serviceIp)
}

func (c *Controller) updatePodPublicIp(service *api.Service, pod *api.Pod) {
	var publicIp *types.FloatingIp
	var err error
	resourceName := publicIpResourceName(service)
	if service.Spec.DeprecatedPublicIPs != nil {
		publicIp, err = c.networkMgr.LocateFloatingIp(c.networkMgr.GetPublicNetwork(), resourceName,
			service.Spec.DeprecatedPublicIPs[0])
	} else if service.Spec.Type == api.ServiceTypeLoadBalancer {
		publicIp, err = c.networkMgr.LocateFloatingIp(c.networkMgr.GetPublicNetwork(), resourceName, "")
	} else {
		return
	}
	if err != nil {
		return
	}
	c.instanceMgr.AttachFloatingIp(pod.Name, pod.Namespace, publicIp)
}

func decodeAccessTag(tag string) []string {
	var strList []string
	err := json.Unmarshal([]byte(tag), &strList)
	if err == nil {
		return strList
	}
	return []string{tag}
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
		serviceList := decodeAccessTag(policyTag)
		for _, srv := range serviceList {
			c.serviceMgr.Connect(pod.Namespace, srv, network)
		}
	}
	// TODO(prm): Disconnect from any policy that the network is associated with other than the
	// policies above.

	for _, item := range c.serviceStore.List() {
		service := item.(*api.Service)
		if service.Namespace != pod.Namespace {
			continue
		}
		if len(service.Spec.Selector) == 0 {
			continue
		}
		selector := labels.SelectorFromSet(service.Spec.Selector)
		if selector.Matches(labels.Set(pod.Labels)) {
			glog.Infof("Pod %s is a member of service %s", pod.Name, service.Name)
			c.updatePodServiceIp(service, pod)
			c.updatePodPublicIp(service, pod)
		}
	}
}

// DeletePod
func (c *Controller) deletePod(pod *api.Pod) {
	glog.Infof("Delete Pod %s", pod.Name)

	c.instanceMgr.ReleaseInstanceIp(pod.Namespace, pod.Name, string(pod.ObjectMeta.UID))
	c.instanceMgr.ReleaseInterface(pod.Namespace, pod.Name)
	c.instanceMgr.DeleteInstance(string(pod.ObjectMeta.UID))

	netname, ok := pod.Labels[c.config.NetworkTag]
	if !ok {
		netname = "default-network"
	}
	deleted, err := c.networkMgr.ReleaseNetworkIfEmpty(pod.Namespace, netname)
	if err != nil {
		glog.Infof("Release network %s: %v", netname, err)
	}

	// TODO(prm): cleanup all the policies
	if deleted {
		policyTag, ok := pod.Labels[c.config.NetworkAccessTag]
		if ok {
			serviceList := decodeAccessTag(policyTag)
			for _, srv := range serviceList {
				c.serviceMgr.Disconnect(pod.Namespace, srv, netname)
			}
		}
	}
}

func (c *Controller) updateServicePublicIP(service *api.Service) (*types.FloatingIp, error) {
	var publicIp *types.FloatingIp = nil
	var err error

	resourceName := publicIpResourceName(service)
	if service.Spec.DeprecatedPublicIPs != nil {
		// Allocate a floating-ip from the public pool.
		publicIp, err = c.networkMgr.LocateFloatingIp(
			c.networkMgr.GetPublicNetwork(), resourceName, service.Spec.DeprecatedPublicIPs[0])
	} else if service.Spec.Type == api.ServiceTypeLoadBalancer {
		publicIp, err = c.networkMgr.LocateFloatingIp(c.networkMgr.GetPublicNetwork(), resourceName, "")
		if err == nil {
			status := api.LoadBalancerStatus{Ingress: []api.LoadBalancerIngress{
				api.LoadBalancerIngress{IP: publicIp.GetFloatingIpAddress()},
			}}
			if !reflect.DeepEqual(service.Status.LoadBalancer, status) {
				service.Status.LoadBalancer = status
				_, err := c.kube.Services(service.Namespace).Update(service)
				if err != nil {
					glog.Infof("Update service %s LB status: %v", service.Name, err)
				}
			}
		}
	}

	return publicIp, err
}

// Services can specify "publicIPs", these are mapped to floating-ip
// addresses. By default a service implies a mapping from a service address
// to the backends.
func (c *Controller) addService(service *api.Service) {
	glog.Infof("Add Service %s", service.Name)
	serviceName := c.serviceName(service.Labels)
	err := c.serviceMgr.Create(service.Namespace, serviceName)
	if err != nil {
		return
	}

	pods, err := c.kube.Pods(service.Namespace).List(
		labels.Set(service.Spec.Selector).AsSelector(), fields.Everything())
	if err != nil {
		glog.Errorf("List pods by service %s: %v", service.Name, err)
		return
	}

	if len(pods.Items) == 0 {
		return
	}

	var serviceIp *types.FloatingIp = nil
	// Allocate this IP address on the service network.
	if service.Spec.ClusterIP != "" {
		serviceNetwork, err := c.serviceMgr.LocateServiceNetwork(service.Namespace, serviceName)
		if err == nil {
			serviceIp, err = c.networkMgr.LocateFloatingIp(
				serviceNetwork, service.Name, service.Spec.ClusterIP)
		}
	}

	publicIp, err := c.updateServicePublicIP(service)

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
}

func (c *Controller) purgeStaleServiceRefs(fip *types.FloatingIp, refs contrail.ReferenceList, podIdMap map[string]*api.Pod) {
	update := false
	for _, ref := range refs {
		vmi, err := types.VirtualMachineInterfaceByUuid(c.client, ref.Uuid)
		if err != nil {
			glog.Errorf("%v", err)
			continue
		}
		instanceRefs, err := vmi.GetVirtualMachineRefs()
		if err != nil {
			glog.Errorf("%v", err)
			continue
		}
		if len(instanceRefs) == 0 {
			continue
		}
		if _, ok := podIdMap[instanceRefs[0].Uuid]; ok {
			continue
		}
		glog.V(3).Infof("Delete reference from pod %s to %s", ref.Uuid, fip.GetFloatingIpAddress())
		fip.DeleteVirtualMachineInterface(vmi.GetUuid())
		update = true
	}

	if update {
		err := c.client.Update(fip)
		if err != nil {
			glog.Errorf("%v", err)
		}
	}
}

func (c *Controller) updateService(service *api.Service) {
	glog.Infof("Update Service %s", service.Name)
	serviceName := c.serviceName(service.Labels)
	err := c.serviceMgr.Create(service.Namespace, serviceName)
	if err != nil {
		return
	}

	pods, err := c.kube.Pods(service.Namespace).List(
		labels.Set(service.Spec.Selector).AsSelector(), fields.Everything())
	if err != nil {
		glog.Errorf("List pods by service %s: %v", service.Name, err)
		return
	}

	var serviceIp *types.FloatingIp = nil
	if service.Spec.ClusterIP != "" {
		serviceNetwork, err := c.serviceMgr.LocateServiceNetwork(service.Namespace, serviceName)
		if err == nil {
			serviceIp, err = c.networkMgr.LocateFloatingIp(
				serviceNetwork, service.Name, service.Spec.ClusterIP)
		}
	} else {
		serviceNetwork, err := c.serviceMgr.LookupServiceNetwork(service.Namespace, serviceName)
		if err == nil {
			c.networkMgr.DeleteFloatingIp(serviceNetwork, service.Name)
		}
	}

	publicIp, err := c.updateServicePublicIP(service)
	if err == nil && publicIp == nil {
		resourceName := publicIpResourceName(service)
		c.networkMgr.DeleteFloatingIp(c.networkMgr.GetPublicNetwork(), resourceName)
	}

	podIdMap := make(map[string]*api.Pod)
	for _, pod := range pods.Items {
		podIdMap[string(pod.UID)] = &pod
		if serviceIp != nil {
			// Connect serviceIp to VMI.
			c.instanceMgr.AttachFloatingIp(pod.Name, pod.Namespace, serviceIp)
		}
		if publicIp != nil {
			c.instanceMgr.AttachFloatingIp(pod.Name, pod.Namespace, publicIp)
		}
	}

	// Detach the VIPs from pods which are no longer selected.
	if serviceIp != nil {
		refs, err := serviceIp.GetVirtualMachineInterfaceRefs()
		if err == nil {
			c.purgeStaleServiceRefs(serviceIp, refs, podIdMap)
		}
	}

	if publicIp != nil {
		refs, err := publicIp.GetVirtualMachineInterfaceRefs()
		if err == nil {
			c.purgeStaleServiceRefs(publicIp, refs, podIdMap)
		}
	}
}

func (c *Controller) deleteService(service *api.Service) {
	glog.Infof("Delete Service %s", service.Name)
	serviceName := c.serviceName(service.Labels)
	serviceNetwork, err := c.serviceMgr.LookupServiceNetwork(service.Namespace, serviceName)
	if err == nil {
		c.networkMgr.DeleteFloatingIp(serviceNetwork, service.Name)
	}
	if service.Spec.DeprecatedPublicIPs != nil || service.Spec.Type == api.ServiceTypeLoadBalancer {
		resourceName := publicIpResourceName(service)
		c.networkMgr.DeleteFloatingIp(c.networkMgr.GetPublicNetwork(), resourceName)
	}

	empty, remaining := c.serviceMgr.IsEmpty(service.Namespace, serviceName)
	if empty {
		c.serviceMgr.Delete(service.Namespace, serviceName)
	} else {
		for _, name := range remaining {
			key := fmt.Sprintf("%s/%s", service.Namespace, name)
			_, exists, _ := c.serviceStore.GetByKey(key)
			if !exists {
				glog.Warningf("Service network %s has floating-ip addresses for service %s (NOT in cache)", serviceName, name)
			}
		}
	}
}

func (c *Controller) addNamespace(namespace *api.Namespace) {
	c.namespaceMgr.LocateNamespace(namespace.Name, string(namespace.ObjectMeta.UID))
}

func (c *Controller) deleteNamespace(namespace *api.Namespace) {
	c.namespaceMgr.DeleteNamespace(namespace.Name)
}
