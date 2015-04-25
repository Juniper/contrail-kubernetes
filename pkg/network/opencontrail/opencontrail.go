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
	"strconv"
	"strings"
	"sync"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	kubeclient "github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/labels"

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
	Kube           *kubeclient.Client
	Client         *contrail.Client
	createLock     *sync.Mutex
	NamespaceStore *cache.Store
	PodStore       *cache.Store
	RCStore        *cache.Store
	ServiceStore   *cache.Store
}

// TODO(prm): use configuration file to modify parameters
const (
	ApiAddress     = "localhost"
	ApiPort        = 8082
	DefaultProject = "default-domain:default-project"
	PublicNetwork  = "default-domain:default-project:Public"
	PublicSubnet   = "10.1.0.0/16"
	PrivateSubnet  = "10.0.0.0/16"
	// TODO: read from kubernetes configuration file.
	ServiceSubnet = "10.254.0.0/16"

	AddressAllocationNetwork = "default-domain:default-project:addr-alloc"
)

func NewController(kube *kubeclient.Client) *Controller {
	controller := new(Controller)
	controller.Kube = kube
	controller.Client = contrail.NewClient(ApiAddress, ApiPort)
	controller.createLock = new(sync.Mutex)
	controller.initializeNetworks()
	return controller
}

func AppendConst(slice []string, element string) []string {
	newSlice := make([]string, len(slice), len(slice)+1)
	copy(newSlice, slice)
	return append(newSlice, element)
}

func PrefixToAddressLen(subnet string) (string, int) {
	prefix := strings.Split(subnet, "/")
	address := prefix[0]
	prefixlen, _ := strconv.Atoi(prefix[1])
	return address, prefixlen
}

func (c *Controller) SetNamespaceStore(store *cache.Store) {
	c.NamespaceStore = store
}

func (c *Controller) SetPodStore(store *cache.Store) {
	c.PodStore = store
}

func (c *Controller) SetReplicationControllerStore(store *cache.Store) {
	c.RCStore = store
}

func (c *Controller) SetServiceStore(store *cache.Store) {
	c.ServiceStore = store
}

func (c *Controller) locateFloatingIpPool(
	network *types.VirtualNetwork, name, subnet string) *types.FloatingIpPool {
	fqn := network.GetFQName()
	fqn = AppendConst(fqn[0:len(fqn)-1], name)
	obj, err := c.Client.FindByName(
		"floating-ip-pool", strings.Join(fqn, ":"))
	if err == nil {
		return obj.(*types.FloatingIpPool)
	}

	// TODO: Use an utility function
	address, prefixlen := PrefixToAddressLen(subnet)

	pool := new(types.FloatingIpPool)
	pool.SetName(name)
	pool.SetParent(network)
	pool.SetFloatingIpPoolPrefixes(
		&types.FloatingIpPoolType{
			Subnet: []types.SubnetType{types.SubnetType{address, prefixlen}}})
	err = c.Client.Create(pool)
	if err != nil {
		glog.Errorf("Create floating-ip-pool %s: %v", name, err)
		return nil
	}
	return pool

}

func (c *Controller) initializePublicNetwork() {
	var network *types.VirtualNetwork
	obj, err := c.Client.FindByName("virtual-network", PublicNetwork)
	if err != nil {
		fqn := strings.Split(PublicNetwork, ":")
		parent := strings.Join(fqn[0:len(fqn)-1], ":")
		projectId, err := c.Client.UuidByName("project", parent)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		networkId, err := config.CreateNetworkWithSubnet(
			c.Client, projectId, fqn[len(fqn)-1], PublicSubnet)
		if err != nil {
			glog.Fatalf("%s: %v", parent, err)
		}
		glog.Infof("Created network %s", PublicNetwork)

		obj, err := c.Client.FindByUuid("virtual-network", networkId)
		if err != nil {
			glog.Fatalf("GET %s %v", networkId, err)
		}
		network = obj.(*types.VirtualNetwork)
	} else {
		network = obj.(*types.VirtualNetwork)
	}
	// TODO(prm): Ensure that the subnet is as specified.
	c.locateFloatingIpPool(network, "Public", PublicSubnet)
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
	obj, err := c.Client.FindByUuid("instance-ip", ipObj.GetUuid())
	if err != nil {
		glog.Infof("Get InstanceIp %s: %v", uid, err)
	}
	ipObj = obj.(*types.InstanceIp)
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

func (c *Controller) lookupNetwork(projectName, networkName string) *types.VirtualNetwork {
	fqn := strings.Split(projectName, ":")
	fqn = AppendConst(fqn, networkName)
	obj, err := c.Client.FindByName("virtual-network", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("GET virtual-network %s: %v", networkName, err)
		return nil
	}
	return obj.(*types.VirtualNetwork)
}

func (c *Controller) locateNetwork(project, name, subnet string) *types.VirtualNetwork {
	fqn := append(strings.Split(project, ":"), name)
	fqname := strings.Join(fqn, ":")

	c.createLock.Lock()
	defer c.createLock.Unlock()

	network, err := c.Client.FindByName("virtual-network", fqname)
	if err != nil {
		projectId, err := c.Client.UuidByName("project", project)
		if err != nil {
			glog.Infof("GET %s: %v", project, err)
			return nil
		}
		uid, err := config.CreateNetworkWithSubnet(
			c.Client, projectId, name, subnet)
		if err != nil {
			glog.Infof("Create %s: %v", name, err)
			return nil
		}
		network, err = c.Client.FindByUuid("virtual-network", uid)
		if err != nil {
			glog.Infof("GET %s: %v", name, err)
			return nil
		}
		glog.Infof("Create network %s", fqname)
	}
	return network.(*types.VirtualNetwork)
}

// assume that labels["name"] names the network
func (c *Controller) getPodNetwork(pod *api.Pod) *types.VirtualNetwork {
	name, ok := pod.Labels["name"]
	if !ok {
		name = "default-network"
	}
	return c.locateNetwork(DefaultProject, name, PrivateSubnet)
}

func (c *Controller) getServiceNetwork(pod *api.Pod) *types.VirtualNetwork {
	name, ok := pod.Labels["name"]
	if !ok {
		name = "services"
	} else {
		name = fmt.Sprintf("service-%s", name)
	}
	network := c.locateNetwork(DefaultProject, name, ServiceSubnet)
	c.locateFloatingIpPool(network, name, ServiceSubnet)
	return network
}

func (c *Controller) locateInstance(pod *api.Pod, project *types.Project) *types.VirtualMachine {
	c.createLock.Lock()
	defer c.createLock.Unlock()

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

func (c *Controller) lookupInterface(project, podName string) *types.VirtualMachineInterface {
	fqn := append(strings.Split(project, ":"), podName)
	obj, err := c.Client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Infof("Get vmi %s: %v", podName, err)
		return nil
	}
	return obj.(*types.VirtualMachineInterface)
}

func (c *Controller) locateInterface(
	pod *api.Pod, project *types.Project, network *types.VirtualNetwork,
	instance *types.VirtualMachine) *types.VirtualMachineInterface {
	fqn := AppendConst(project.GetFQName(), pod.Name)

	c.createLock.Lock()
	defer c.createLock.Unlock()

	obj, err := c.Client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))

	if err == nil {
		nic := obj.(*types.VirtualMachineInterface)
		// TODO(prm): ensure network is as expected, else update.
		return nic
	}

	nic := new(types.VirtualMachineInterface)
	nic.SetName(pod.Name)
	nic.SetParent(project)
	nic.AddVirtualMachine(instance)
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

	c.createLock.Lock()
	defer c.createLock.Unlock()

	obj, err := c.Client.FindByName("instance-ip", pod.ObjectMeta.Name)
	if err == nil {
		// TODO(prm): ensure that attributes are as expected
		return obj.(*types.InstanceIp)
	}

	address := c.allocateIpAddress(string(pod.ObjectMeta.UID))
	glog.Infof("%s IP address: %s", pod.Name, address)

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

func (c *Controller) updatePodInterface(pod *api.Pod, nic *types.VirtualMachineInterface) {

	// Modify the POD object such that its Annotations['vmi'] is
	// updated with the UUID of the nic
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	pod.Annotations["vmi"] = nic.GetUuid()
	_, err := c.Kube.Pods(pod.Namespace).Update(pod)
	if err != nil {
		glog.Errorf("Pod Update %s: %v", pod.Name, err)
		return
	}
	glog.Infof("Set annotation on pod %s 'vmi'=%s", pod.Name, nic.GetUuid())
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
	glog.Infof("Add Pod %s", pod.Name)

	// TODO(prm): use namespace for project
	obj, err := c.Client.FindByName("project", DefaultProject)
	if err != nil {
		glog.Fatalf("%s: %v", DefaultProject, err)
	}

	project := obj.(*types.Project)
	instance := c.locateInstance(pod, project)

	network := c.getPodNetwork(pod)
	if network == nil {
		return
	}

	nic := c.locateInterface(pod, project, network, instance)
	c.locateInstanceIp(pod, network, nic)

	c.updatePodInterface(pod, nic)

	policyTag, ok := pod.Labels["uses"]
	if ok {
		var policyName string
		if pod.GenerateName == "" {
			policyName = pod.Name
		} else {
			policyName = strings.TrimRight(pod.GenerateName, "-")
		}
		serviceName := fmt.Sprintf("service-%s", policyTag)
		c.networkAccess(network, policyName, serviceName)
	}
}

func (c *Controller) UpdatePod(oldPod, newPod *api.Pod) {
	glog.Infof("Update Pod %s", newPod.Name)
	var update bool = false
	if newPod.Annotations == nil {
		update = true
	} else {
		_, ok := newPod.Annotations["vmi"]
		if !ok {
			update = true
		}
	}

	if update {
		// TODO(prm): use namespace for project
		nic := c.lookupInterface(DefaultProject, newPod.Name)
		if nic != nil {
			c.updatePodInterface(newPod, nic)
		}
	}
}

// DeletePod
func (c *Controller) DeletePod(pod *api.Pod) {
	glog.Infof("Delete Pod %s", pod.Name)

	// TODO(prm): use namespace for project
	obj, err := c.Client.FindByName("project", DefaultProject)
	if err != nil {
		glog.Fatalf("%s: %v", DefaultProject, err)
	}
	project := obj.(*types.Project)

	fqn := AppendConst(project.GetFQName(), pod.Name)
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

func (c *Controller) locatePolicyRule(policy *types.NetworkPolicy, lhs, rhs *types.VirtualNetwork) {
	lhsName := strings.Join(lhs.GetFQName(), ":")
	rhsName := strings.Join(rhs.GetFQName(), ":")

	entries := policy.GetNetworkPolicyEntries()
	for _, rule := range entries.PolicyRule {
		if rule.SrcAddresses[0].VirtualNetwork == lhsName &&
			rule.DstAddresses[0].VirtualNetwork == rhsName {
			return
		}
	}
	rule := new(types.PolicyRuleType)
	rule.Protocol = "any"
	rule.Direction = "<>"
	rule.SrcAddresses = []types.AddressType{types.AddressType{
		VirtualNetwork: lhsName,
	}}
	rule.DstAddresses = []types.AddressType{types.AddressType{
		VirtualNetwork: rhsName,
	}}
	rule.SrcPorts = []types.PortType{types.PortType{-1, -1}}
	rule.DstPorts = []types.PortType{types.PortType{-1, -1}}
	rule.ActionList = &types.ActionListType{
		SimpleAction: "pass",
	}

	entries.AddPolicyRule(rule)
	policy.SetNetworkPolicyEntries(&entries)
	err := c.Client.Update(policy)
	if err != nil {
		glog.Errorf("policy-rule: %v", err)
	}
}

func (c *Controller) attachPolicy(network *types.VirtualNetwork, policy *types.NetworkPolicy) {
	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		glog.Errorf("get network policy-refs %s: %v", network.GetName(), err)
		return
	}
	for _, ref := range refs {
		if ref.Uuid == policy.GetUuid() {
			return
		}
	}
	network.AddNetworkPolicy(policy,
		types.VirtualNetworkPolicyType{
			Sequence: &types.SequenceType{10, 0},
		})
	err = c.Client.Update(network)
	if err != nil {
		glog.Errorf("Update network %s policies: %v", network.GetName(), err)
	}
}

// create a policy that connects two networks.
func (c *Controller) networkAccess(
	network *types.VirtualNetwork, policyName, policyTag string) {
	glog.Infof("policy %s: %s <=> %s", policyName, network.GetName(), policyTag)
	networkFQN := network.GetFQName()
	fqn := AppendConst(networkFQN[0:len(networkFQN)-1], policyName)

	c.createLock.Lock()
	defer c.createLock.Unlock()

	var policy *types.NetworkPolicy = nil
	obj, err := c.Client.FindByName("network-policy", strings.Join(fqn, ":"))

	if err != nil {
		policy = new(types.NetworkPolicy)
		policy.SetFQName("project", fqn)
		err = c.Client.Create(policy)
		if err != nil {
			glog.Errorf("Create policy %s: %v", policyName, err)
			return
		}
	} else {
		policy = obj.(*types.NetworkPolicy)
	}

	rhsName := AppendConst(networkFQN[0:len(networkFQN)-1], policyTag)
	obj, err = c.Client.FindByName("virtual-network", strings.Join(rhsName, ":"))
	if err != nil {
		glog.Errorf("GET virtual-network %s: %v", policyTag, err)
		return
	}
	rhsNetwork := obj.(*types.VirtualNetwork)
	c.locatePolicyRule(policy, network, rhsNetwork)
	c.attachPolicy(network, policy)
	c.attachPolicy(rhsNetwork, policy)
}

func (c *Controller) AddReplicationController(rc *api.ReplicationController) {
	glog.Infof("Add RC %s", rc.Name)
}

func (c *Controller) UpdateReplicationController(
	oldObj, newObj *api.ReplicationController) {
	glog.Infof("Update RC %s", newObj.Name)
}

func (c *Controller) DeleteReplicationController(
	rc *api.ReplicationController) {
	// TODO: delete policies.
	glog.Infof("Delete RC %s", rc.Name)
}

func (c *Controller) attachServiceIp(
	pod *api.Pod, network *types.VirtualNetwork, serviceIp *types.InstanceIp) {
	networkFQN := network.GetFQName()
	fqn := AppendConst(networkFQN[0:len(networkFQN)-1], pod.Name)
	obj, err := c.Client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("GET vmi %s: %v", pod.Name, err)
		return
	}

	vmi := obj.(*types.VirtualMachineInterface)

	refs, err := serviceIp.GetVirtualMachineInterfaceRefs()
	if err != nil {
		glog.Errorf("GET instance-ip %s: %v", serviceIp.GetUuid(), err)
		return
	}
	for _, ref := range refs {
		if ref.Uuid == vmi.GetUuid() {
			return
		}
	}

	serviceIp.AddVirtualMachineInterface(vmi)
	err = c.Client.Update(serviceIp)
	if err != nil {
		glog.Errorf("Update instance-ip %s: %v", pod.Name, err)
	}
}

func (c *Controller) locateFloatingIp(networkName, resourceName, address string) *types.FloatingIp {
	poolName := fmt.Sprintf("%s:%s", DefaultProject, networkName)
	obj, err := c.Client.FindByName("floating-ip-pool", poolName)
	if err != nil {
		glog.Errorf("Get floating-ip-pool %s: %v", poolName, err)
		return nil
	}
	pool := obj.(*types.FloatingIpPool)

	fqn := AppendConst(pool.GetFQName(), resourceName)
	obj, err = c.Client.FindByName("floating-ip", strings.Join(fqn, ":"))
	if err == nil {
		fip := obj.(*types.FloatingIp)
		if fip.GetFloatingIpAddress() != address {
			fip.SetFloatingIpAddress(address)
			err = c.Client.Update(fip)
			if err != nil {
				glog.Errorf("Update floating-ip %s: %v", resourceName, err)
				return nil
			}
		}
		return fip
	}

	obj, err = c.Client.FindByName("project", DefaultProject)
	if err != nil {
		glog.Errorf("Get project %s: %v", DefaultProject, err)
		return nil
	}
	project := obj.(*types.Project)

	fip := new(types.FloatingIp)
	fip.SetParent(pool)
	fip.SetName(resourceName)
	fip.SetFloatingIpAddress(address)
	fip.AddProject(project)
	err = c.Client.Create(fip)
	if err != nil {
		glog.Errorf("Create floating-ip %s: %v", resourceName, err)
		return nil
	}
	return fip
}

func (c *Controller) attachFloatingIp(
	pod *api.Pod, projectName string, floatingIp *types.FloatingIp) {

	fqn := AppendConst(strings.Split(projectName, ":"), pod.Name)
	obj, err := c.Client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("GET vmi %s: %v", pod.Name, err)
		return
	}

	vmi := obj.(*types.VirtualMachineInterface)

	refs, err := floatingIp.GetVirtualMachineInterfaceRefs()
	if err != nil {
		glog.Errorf("GET floating-ip %s: %v", floatingIp.GetUuid(), err)
		return
	}
	for _, ref := range refs {
		if ref.Uuid == vmi.GetUuid() {
			return
		}
	}

	floatingIp.AddVirtualMachineInterface(vmi)
	err = c.Client.Update(floatingIp)
	if err != nil {
		glog.Errorf("Update floating-ip %s: %v", pod.Name, err)
	}
}

// Services can specify "publicIPs", these are mapped to floating-ip
// addresses. By default a service implies a mapping from a service address
// to the backends.
func (c *Controller) AddService(service *api.Service) {
	glog.Infof("Add Service %s", service.Name)

	pods, err := c.Kube.Pods(service.Namespace).List(
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
		serviceNetwork = c.getServiceNetwork(&pods.Items[0])
		if serviceNetwork != nil {
			serviceIp = c.locateFloatingIp(serviceNetwork.GetName(), service.Name, service.Spec.PortalIP)
		}
	}

	var publicIp *types.FloatingIp = nil
	if service.Spec.PublicIPs != nil {
		// Allocate a floating-ip from the public pool.
		publicIp = c.locateFloatingIp("Public", service.Name, service.Spec.PublicIPs[0])
	}

	if serviceIp == nil && publicIp == nil {
		return
	}

	for _, pod := range pods.Items {
		if serviceIp != nil {
			// Connect serviceIp to VMI.
			c.attachFloatingIp(&pod, DefaultProject, serviceIp)
		}
		if publicIp != nil {
			c.attachFloatingIp(&pod, DefaultProject, publicIp)
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

func (c *Controller) UpdateService(oldObj, newObj *api.Service) {
	glog.Infof("Update Service %s", newObj.Name)
}

func (c *Controller) DeleteService(service *api.Service) {
	glog.Infof("Delete Service %s", service.Name)
}
