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

// The OpenContrail controller maps kubernetes objects into networking
// properties such that:
// - Each Pod/Replication controller is assigned to a network, depending on the isolation mode
// - Labels are used to connect virtual networks
// - Services allocate floating-ip addresses.

type Controller struct {
	kube kubeclient.Interface

	client contrail.ApiClient
	config *Config

	eventChannel chan notification

	podStore     cache.Indexer
	serviceStore cache.Store
	namespaceStore cache.Store

	instanceMgr  *InstanceManager
	networkMgr   NetworkManager
	serviceMgr   ServiceManager
	namespaceMgr *NamespaceManager
	allocator    AddressAllocator

	consistencyPeriod time.Duration
	consistencyWorker ConsistencyChecker

	virtualRouterUpdatePeriod time.Duration
	virtualRouterMgr          *VirtualRouterManager
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
//			c.consistencyWorker.Check()
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

	newValue.Uuid = nic.GetUuid()
	var mac_address string
	addressArr := nic.GetVirtualMachineInterfaceMacAddresses()
	if len(addressArr.MacAddress) > 0 {
		mac_address = addressArr.MacAddress[0]
	} else {
		glog.Errorf("interface %s: no mac-addresses", nic.GetName())
	}
	newValue.MacAddress = mac_address
	newValue.IpAddress = address
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

func getPodNetworkName(pod *api.Pod, config *Config) string {
	name, ok := pod.Labels[config.NetworkTag]
	if !ok {
		name = ClusterNetworkName
	}
	return name
}

// Retrieve the private network for this Pod.
func (c *Controller) GetPodNetwork(pod *api.Pod) *types.VirtualNetwork {
	// network will depend on the isolation mode
	network, err := c.networkMgr.LookupNetwork(DefaultServiceProjectName, ClusterNetworkName)
	if err != nil {
		glog.Errorf("Cannot get cluster-network")
	}
	return network
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
	if service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" {
		return
	}

	serviceNetwork := c.serviceMgr.GetServiceNetwork(service)
	if serviceNetwork == nil {
		glog.Errorf("Service network not found")
		return
	}
	serviceIp, err := c.networkMgr.LocateFloatingIp(serviceNetwork, service.Name, service.Spec.ClusterIP)
	if err != nil {
		glog.Error(err)
		return
	}
	c.instanceMgr.AttachFloatingIp(pod.Name, pod.Namespace, serviceIp)
}

func (c *Controller) updatePodPublicIp(service *api.Service, pod *api.Pod) {
	var publicIp *types.FloatingIp
	var err error
	resourceName := publicIpResourceName(service)
	if service.Spec.ExternalIPs != nil {
		publicIp, err = c.networkMgr.LocateFloatingIp(c.networkMgr.GetPublicNetwork(), resourceName,
			service.Spec.ExternalIPs[0])
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

func buildPodServiceList(pod *api.Pod, config *Config, serviceList *ServiceIdList) {
	for _, svc := range config.ClusterServices {
		namespace, service := serviceIdFromName(svc)
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

	podNetwork := c.GetPodNetwork(pod)
	if podNetwork == nil {
		glog.Errorf("Pod network not found")
		return
	}

	c.globalNetworkConnectionUpdate(podNetwork)
	nic := c.instanceMgr.LocateInterface(pod.Namespace, podNetwork, instance)
	if nic == nil {
		return
	}
	address := c.instanceMgr.LocateInstanceIp(podNetwork, string(pod.ObjectMeta.UID), nic)
	if address == nil {
		return
	}
	gateway, err := c.networkMgr.GetGatewayAddress(podNetwork)
	if err != nil {
		return
	}
	c.updateInstanceMetadata(pod, nic, address.GetInstanceIpAddress(), gateway)

	//TODO Policies not needed for now
	/*
	c.serviceMgr.ConnectNetworks(podNetwork, c.networkMgr.GetClusterNetwork())

	serviceList := MakeServiceIdList()
	buildPodServiceList(pod, c.config, &serviceList)
	for _, srv := range serviceList {
		c.serviceMgr.Connect(podNetwork, srv.Namespace, srv.Service)
	}*/

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
	result := c.virtualRouterMgr.addPodRefToVirtualRouter(pod, instance)
	if result {
		return
	}
}

// DeletePod
func (c *Controller) deletePod(pod *api.Pod) {
	glog.Infof("Delete Pod %s", pod.Name)

	instance := c.instanceMgr.LocateInstance(pod.Namespace, pod.Name, string(pod.ObjectMeta.UID))
	if instance != nil {
		result := c.virtualRouterMgr.removePodRefFromVirtualRouter(pod, instance)
		if result {
			glog.Infof("pod(%s) removed from vRouter(%s)", pod.Name, pod.Status.HostIP)
		}
	}

	c.instanceMgr.ReleaseInstanceIp(pod.Namespace, pod.Name, string(pod.ObjectMeta.UID))
	c.instanceMgr.ReleaseInterface(pod.Namespace, pod.Name)
	c.instanceMgr.DeleteInstance(string(pod.ObjectMeta.UID))

	podNetwork := c.GetPodNetwork(pod)
	if podNetwork == nil {
		glog.Errorf("Pod network not found")
		return
	}

	deleted, err := c.networkMgr.ReleaseNetworkIfEmpty(podNetwork)
	if err != nil {
		glog.Errorf("Release network %s: %v", podNetwork.GetName(), err)
	}

	if deleted {
		serviceList := MakeServiceIdList()
		buildPodServiceList(pod, c.config, &serviceList)
		for _, srv := range serviceList {
			c.serviceMgr.Disconnect(podNetwork, srv.Namespace, srv.Service)
		}

		networkFQN := []string{c.config.DefaultDomain, pod.Namespace, podNetwork.GetName()}
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
	var publicIp *types.FloatingIp = nil
	var err error

	resourceName := publicIpResourceName(service)
	if service.Spec.ExternalIPs != nil {
		// Allocate a floating-ip from the public pool.
		publicIp, err = c.networkMgr.LocateFloatingIp(
			c.networkMgr.GetPublicNetwork(), resourceName, service.Spec.ExternalIPs[0])
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

	err := c.serviceMgr.Create(service)
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

	serviceNetwork := c.serviceMgr.GetServiceNetwork(service)
	if serviceNetwork == nil {
		glog.Errorf("Service network not found")
		return
	}
	var serviceIp *types.FloatingIp
	// Allocate this IP address on the service network.
	if service.Spec.ClusterIP != ""  && service.Spec.ClusterIP != "None" {
		serviceIp, err = c.networkMgr.LocateFloatingIp(
			serviceNetwork, service.Name, service.Spec.ClusterIP)
		if err != nil {
			glog.Error(err)
		} else {
			glog.V(3).Infof("Created floating-ip %s for %s/%s", service.Spec.ClusterIP, service.Namespace, service.Name)
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

	c.ensureNamespace(service.Namespace)

	err := c.serviceMgr.Create(service)
	if err != nil {
		return
	}

	pods, err := c.kube.Pods(service.Namespace).List(makeListOptSelector(service.Spec.Selector))
	if err != nil {
		glog.Errorf("List pods by service %s: %v", service.Name, err)
		return
	}

	var serviceIp *types.FloatingIp = nil
	serviceNetwork := c.serviceMgr.GetServiceNetwork(service)
	if serviceNetwork == nil {
		glog.Errorf("Service network not found")
		return
	}
	if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
		serviceIp, err = c.networkMgr.LocateFloatingIp(
			serviceNetwork, service.Name, service.Spec.ClusterIP)
	} else {
		c.networkMgr.DeleteFloatingIp(serviceNetwork, service.Name)
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

	serviceNetwork := c.serviceMgr.GetServiceNetwork(service)
	if serviceNetwork == nil {
		glog.Errorf("Service network not found")
		return
	}

	c.networkMgr.DeleteFloatingIp(serviceNetwork, service.Name)

	if service.Spec.ExternalIPs != nil || service.Spec.Type == api.ServiceTypeLoadBalancer {
		resourceName := publicIpResourceName(service)
		c.networkMgr.DeleteFloatingIp(c.networkMgr.GetPublicNetwork(), resourceName)
	}

	c.serviceMgr.Delete(service)
}

func (c *Controller) addNamespace(namespace *api.Namespace) {
	c.namespaceMgr.LocateNamespace(namespace.Name, string(namespace.ObjectMeta.UID))
}

func (c *Controller) deleteNamespace(namespace *api.Namespace) {
	c.namespaceMgr.DeleteNamespace(namespace.Name)
}
