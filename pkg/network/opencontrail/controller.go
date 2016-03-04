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
	"strings"
	"time"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	kubeclient "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/runtime"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

// Controller maps kubernetes objects into networking properties such that:
// - Pods are associated with pod-networks specified via "domain:namespace:<NetworkTag>"
// - Service ClusterIP addresses are assigned to service-networks, which have a name
//   of "domain:namespace:service-<NetworkTag>"; clusterIP addresses are floating-ips assigned
//   to the Pods (endpoints) selected by the service.
// - Labels <NetworkAccessTag> are used to connect pod networks to service networks.
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
	evSync            eventType = "Sync"
)

type notification struct {
	event  eventType
	object runtime.Object
}

func (c *Controller) newConsistencyChecker() ConsistencyChecker {
	return NewConsistencyChecker(c.client, c.config, c.podStore, c.serviceStore, c.networkMgr, c.serviceMgr)
}

// Run executes the Controller main loop. It returns when the shutdown channel receives a message.
func (c *Controller) Run(shutdown chan struct{}) {
	var timerChan <-chan time.Time

	if c.consistencyPeriod != 0 {
		glog.V(3).Infof("Consistency checker interval %s", c.consistencyPeriod.String())
		timerChan = time.NewTicker(c.consistencyPeriod).C
		c.consistencyWorker = c.newConsistencyChecker()
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
			case evSync:
			}
		case <-timerChan:
			c.consistencyWorker.Check()
		case <-shutdown:
			return
		}
	}
}

func (c *Controller) updateInstanceMetadata(
	pod *api.Pod, nic *types.VirtualMachineInterface, address, gateway string) {
	doUpdate := false

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
		doUpdate = true
	}

	var newValue, oldValue InstanceMetadata
	if data, ok := pod.Annotations[MetadataAnnotationTag]; ok {
		json.Unmarshal([]byte(data), &oldValue)
	}

	newValue.UUID = nic.GetUuid()
	var macAddress string
	addressArr := nic.GetVirtualMachineInterfaceMacAddresses()
	if len(addressArr.MacAddress) > 0 {
		macAddress = addressArr.MacAddress[0]
	} else {
		glog.Errorf("interface %s: no mac-addresses", nic.GetName())
	}
	newValue.MacAddress = macAddress
	newValue.IPAddress = address
	newValue.Gateway = gateway

	if !doUpdate && reflect.DeepEqual(newValue, oldValue) {
		return
	}

	encoded, err := json.Marshal(&newValue)
	if err != nil {
		glog.Errorf("JSON encode: %v", err)
		return
	}
	pod.Annotations[MetadataAnnotationTag] = string(encoded)
	_, err = c.kube.Pods(pod.Namespace).Update(pod)
	if err != nil {
		// Update will return an error if the pod object that we are
		// working with is stale.
		glog.Infof("Pod Update %s: %v", pod.Name, err)
	}
}

func podNetworkName(pod *api.Pod, config *Config) string {
	name, ok := pod.Labels[config.NetworkTag]
	if !ok {
		name = DefaultPodNetworkName
	}
	return name
}

// Retrieve the private network for this Pod.
func (c *Controller) getPodNetwork(pod *api.Pod) *types.VirtualNetwork {
	name := podNetworkName(pod, c.config)
	network, err := c.networkMgr.LocateNetwork(pod.Namespace, name, c.config.PrivateSubnet)
	if err != nil {
		return nil
	}
	return network
}

func serviceName(config *Config, labels map[string]string) string {
	name, ok := labels[config.NetworkTag]
	if !ok {
		return DefaultServiceNetworkName
	}

	return name
}

// Include the namespace in the resource name so one can deploy the same service in different namespaces.
func publicIPResourceName(service *api.Service) string {
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

func (c *Controller) updatePodServiceIP(service *api.Service, pod *api.Pod) {
	if service.Spec.ClusterIP == "" {
		return
	}

	serviceName := serviceName(c.config, service.Labels)
	serviceNetwork, err := c.serviceMgr.LocateServiceNetwork(service.Namespace, serviceName)
	if err != nil {
		glog.Error(err)
		return
	}
	serviceIP, err := c.networkMgr.LocateFloatingIP(serviceNetwork, service.Name, service.Spec.ClusterIP)
	if err != nil {
		glog.Error(err)
		return
	}
	c.instanceMgr.AttachFloatingIP(pod.Name, pod.Namespace, serviceIP)
}

func (c *Controller) updatePodPublicIP(service *api.Service, pod *api.Pod) {
	var publicIP *types.FloatingIp
	var err error
	resourceName := publicIPResourceName(service)
	if service.Spec.ExternalIPs != nil {
		publicIP, err = c.networkMgr.LocateFloatingIP(c.networkMgr.GetPublicNetwork(), resourceName,
			service.Spec.ExternalIPs[0])
	} else if service.Spec.Type == api.ServiceTypeLoadBalancer {
		publicIP, err = c.networkMgr.LocateFloatingIP(c.networkMgr.GetPublicNetwork(), resourceName, "")
	} else {
		return
	}
	if err != nil {
		return
	}
	c.instanceMgr.AttachFloatingIP(pod.Name, pod.Namespace, publicIP)
}

func decodeAccessTag(tag string) []string {
	var strList []string
	err := json.Unmarshal([]byte(tag), &strList)
	if err == nil {
		return strList
	}
	return []string{tag}
}

func buildPodServiceList(pod *api.Pod, config *Config, serviceList *serviceIDList) {
	for _, svc := range config.ClusterServices {
		namespace, service := serviceIDFromName(svc)
		serviceList.Add(namespace, service)
	}
	for _, svc := range config.NamespaceServices {
		serviceList.Add(pod.Namespace, svc)
	}

	policyTag, ok := pod.Labels[config.NetworkAccessTag]
	if ok {
		serviceLabels := decodeAccessTag(policyTag)
		for _, srv := range serviceLabels {
			serviceList.Add(pod.Namespace, srv)
		}
	}

	policyTag, ok = pod.Annotations[config.NetworkAccessTag]
	if ok {
		serviceLabels := decodeAccessTag(policyTag)
		for _, srv := range serviceLabels {
			serviceList.Add(pod.Namespace, srv)
		}
	}
}

func makeListOptSelector(labelMap map[string]string) api.ListOptions {
	return api.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set(labelMap))}
}

func (c *Controller) updatePod(pod *api.Pod) {
	glog.Infof("Update Pod %s", pod.Name)

	c.ensureNamespace(pod.Namespace)
	instance := c.instanceMgr.LocateInstance(pod.Namespace, pod.Name, string(pod.ObjectMeta.UID))

	network := c.getPodNetwork(pod)
	if network == nil {
		return
	}
	c.globalNetworkConnectionUpdate(network)
	nic := c.instanceMgr.LocateInterface(network, instance)
	if nic == nil {
		return
	}
	address := c.instanceMgr.LocateInstanceIP(network, string(pod.ObjectMeta.UID), nic)
	if address == nil {
		return
	}
	gateway, err := c.networkMgr.GetGatewayAddress(network)
	if err != nil {
		return
	}
	c.updateInstanceMetadata(pod, nic, address.GetInstanceIpAddress(), gateway)

	serviceList := makeServiceIDList()
	buildPodServiceList(pod, c.config, &serviceList)
	for _, srv := range serviceList {
		c.serviceMgr.Connect(srv.Namespace, srv.Service, network)
	}

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
			c.updatePodServiceIP(service, pod)
			c.updatePodPublicIP(service, pod)
		}
	}
}

// DeletePod
func (c *Controller) deletePod(pod *api.Pod) {
	glog.Infof("Delete Pod %s", pod.Name)

	c.instanceMgr.ReleaseInstanceIP(pod.Namespace, pod.Name, string(pod.ObjectMeta.UID))
	c.instanceMgr.ReleaseInterface(pod.Namespace, pod.Name)
	c.instanceMgr.DeleteInstance(string(pod.ObjectMeta.UID))

	networkName := podNetworkName(pod, c.config)
	deleted, err := c.networkMgr.ReleaseNetworkIfEmpty(pod.Namespace, networkName)
	if err != nil {
		glog.Infof("Release network %s: %v", networkName, err)
	}

	if deleted {
		serviceList := makeServiceIDList()
		buildPodServiceList(pod, c.config, &serviceList)
		for _, srv := range serviceList {
			c.serviceMgr.Disconnect(srv.Namespace, srv.Service, networkName)
		}

		networkFQN := []string{c.config.DefaultDomain, pod.Namespace, networkName}
		if networkAccessGlobalNetworks(c.config, networkFQN) {
			for _, gbl := range c.config.GlobalNetworks {
				err = c.networkMgr.Disconnect(networkFQN, gbl)
				if err != nil {
					glog.Error(err)
				}
			}
		}
	}
}

func (c *Controller) updateServicePublicIP(service *api.Service) (*types.FloatingIp, error) {
	var publicIP *types.FloatingIp
	var err error

	resourceName := publicIPResourceName(service)
	if service.Spec.ExternalIPs != nil {
		// Allocate a floating-ip from the public pool.
		publicIP, err = c.networkMgr.LocateFloatingIP(
			c.networkMgr.GetPublicNetwork(), resourceName, service.Spec.ExternalIPs[0])
	} else if service.Spec.Type == api.ServiceTypeLoadBalancer {
		publicIP, err = c.networkMgr.LocateFloatingIP(c.networkMgr.GetPublicNetwork(), resourceName, "")
		if err == nil {
			status := api.LoadBalancerStatus{Ingress: []api.LoadBalancerIngress{
				api.LoadBalancerIngress{IP: publicIP.GetFloatingIpAddress()},
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

	return publicIP, err
}

func (c *Controller) globalNetworkConnectionUpdate(network *types.VirtualNetwork) {
	if !networkAccessGlobalNetworks(c.config, network.GetFQName()) {
		return
	}
	// connect to each of the global-networks
	for _, gbl := range c.config.GlobalNetworks {
		err := c.networkMgr.Connect(network, gbl)
		if err != nil {
			glog.Error(err)
			continue
		}
		glog.V(2).Infof("Connected %s to %s", strings.Join(network.GetFQName(), ":"), gbl)
	}
}

// Services can specify "publicIPs", these are mapped to floating-ip
// addresses. By default a service implies a mapping from a service address
// to the backends.
func (c *Controller) addService(service *api.Service) {
	glog.Infof("Add Service %s", service.Name)
	c.ensureNamespace(service.Namespace)
	serviceName := serviceName(c.config, service.Labels)
	err := c.serviceMgr.Create(service.Namespace, serviceName)
	if err != nil {
		return
	}

	pods, err := c.kube.Pods(service.Namespace).List(makeListOptSelector(service.Spec.Selector))
	if err != nil {
		glog.Errorf("List pods by service %s: %v", service.Name, err)
		return
	}

	if len(pods.Items) == 0 {
		glog.V(5).Infof("No existing pods for service %s", service.Name)
		return
	}

	var serviceIP *types.FloatingIp
	// Allocate this IP address on the service network.
	if service.Spec.ClusterIP != "" {
		serviceNetwork, err := c.serviceMgr.LocateServiceNetwork(service.Namespace, serviceName)
		if err == nil {
			serviceIP, err = c.networkMgr.LocateFloatingIP(
				serviceNetwork, service.Name, service.Spec.ClusterIP)
			if err != nil {
				glog.Error(err)
			} else {
				glog.V(3).Infof("Created floating-ip %s for %s/%s", service.Spec.ClusterIP, service.Namespace, service.Name)
			}
		} else {
			glog.Error(err)
		}
	}

	publicIP, err := c.updateServicePublicIP(service)

	if serviceIP == nil && publicIP == nil {
		return
	}

	for _, pod := range pods.Items {
		if serviceIP != nil {
			// Connect serviceIP to VMI.
			c.instanceMgr.AttachFloatingIP(pod.Name, pod.Namespace, serviceIP)
		}
		if publicIP != nil {
			c.instanceMgr.AttachFloatingIP(pod.Name, pod.Namespace, publicIP)
		}
	}
}

func (c *Controller) purgeStaleServiceRefs(fip *types.FloatingIp, refs contrail.ReferenceList, podIDMap map[string]*api.Pod) {
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
		if _, ok := podIDMap[instanceRefs[0].Uuid]; ok {
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
	serviceName := serviceName(c.config, service.Labels)
	err := c.serviceMgr.Create(service.Namespace, serviceName)
	if err != nil {
		return
	}

	pods, err := c.kube.Pods(service.Namespace).List(makeListOptSelector(service.Spec.Selector))
	if err != nil {
		glog.Errorf("List pods by service %s: %v", service.Name, err)
		return
	}

	var serviceIP *types.FloatingIp
	if service.Spec.ClusterIP != "" {
		serviceNetwork, err := c.serviceMgr.LocateServiceNetwork(service.Namespace, serviceName)
		if err == nil {
			serviceIP, err = c.networkMgr.LocateFloatingIP(
				serviceNetwork, service.Name, service.Spec.ClusterIP)
		}
	} else {
		serviceNetwork, err := c.serviceMgr.LookupServiceNetwork(service.Namespace, serviceName)
		if err == nil {
			c.networkMgr.DeleteFloatingIP(serviceNetwork, service.Name)
		}
	}

	publicIP, err := c.updateServicePublicIP(service)
	if err == nil && publicIP == nil {
		resourceName := publicIPResourceName(service)
		c.networkMgr.DeleteFloatingIP(c.networkMgr.GetPublicNetwork(), resourceName)
	}

	podIDMap := make(map[string]*api.Pod)
	for _, pod := range pods.Items {
		podIDMap[string(pod.UID)] = &pod
		if serviceIP != nil {
			// Connect serviceIP to VMI.
			c.instanceMgr.AttachFloatingIP(pod.Name, pod.Namespace, serviceIP)
		}
		if publicIP != nil {
			c.instanceMgr.AttachFloatingIP(pod.Name, pod.Namespace, publicIP)
		}
	}

	// Detach the VIPs from pods which are no longer selected.
	if serviceIP != nil {
		refs, err := serviceIP.GetVirtualMachineInterfaceRefs()
		if err == nil {
			c.purgeStaleServiceRefs(serviceIP, refs, podIDMap)
		}
	}

	if publicIP != nil {
		refs, err := publicIP.GetVirtualMachineInterfaceRefs()
		if err == nil {
			c.purgeStaleServiceRefs(publicIP, refs, podIDMap)
		}
	}
}

func (c *Controller) deleteService(service *api.Service) {
	glog.Infof("Delete Service %s", service.Name)
	serviceName := serviceName(c.config, service.Labels)
	serviceNetwork, err := c.serviceMgr.LookupServiceNetwork(service.Namespace, serviceName)
	if err == nil {
		c.networkMgr.DeleteFloatingIP(serviceNetwork, service.Name)
	}
	if service.Spec.ExternalIPs != nil || service.Spec.Type == api.ServiceTypeLoadBalancer {
		resourceName := publicIPResourceName(service)
		c.networkMgr.DeleteFloatingIP(c.networkMgr.GetPublicNetwork(), resourceName)
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
