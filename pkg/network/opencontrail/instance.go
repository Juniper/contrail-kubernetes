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

	"github.com/golang/glog"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

// InstanceManager defines the interface between the Controller and the class that
// manages instance (types.VirtualMachine) objects corresponding to Pods.
type InstanceManager struct {
	client    contrail.ApiClient
	config    *Config
	allocator AddressAllocator
}

// NewInstanceManager allocates and initializes an Instance Manager
func NewInstanceManager(client contrail.ApiClient, config *Config, allocator AddressAllocator) *InstanceManager {
	manager := new(InstanceManager)
	manager.client = client
	manager.config = config
	manager.allocator = allocator
	return manager
}

func instanceFQName(domain, tenant, podName string) []string {
	fqn := []string{domain, tenant, podName}
	return fqn
}

// LocateInstance returns a VirtualMachine object corresponding to a Pod name/ID.
// Creating the object if it is not already present in the contrail API.
func (m *InstanceManager) LocateInstance(tenant, podName, uid string) *types.VirtualMachine {
	obj, err := m.client.FindByUuid("virtual-machine", string(uid))
	if err == nil {
		return obj.(*types.VirtualMachine)
	}

	instance := new(types.VirtualMachine)
	instance.SetFQName("project", instanceFQName(m.config.DefaultDomain, tenant, podName))
	instance.SetUuid(uid)
	err = m.client.Create(instance)
	if err != nil {
		glog.Errorf("Create %s: %v", podName, err)
		return nil
	}
	return instance
}

// DeleteInstance deletes the VirtualMachine object from the contrail API.
func (m *InstanceManager) DeleteInstance(uid string) error {
	err := m.client.DeleteByUuid("virtual-machine", uid)
	return err
}

func interfaceFQName(defaultDomain, tenant, podName string) []string {
	fqn := []string{defaultDomain, tenant, podName}
	return fqn
}

// LookupInterface returns the VMI corresponding to a Pod, if it exists
func (m *InstanceManager) LookupInterface(tenant, podName string) *types.VirtualMachineInterface {
	fqn := interfaceFQName(m.config.DefaultDomain, tenant, podName)
	obj, err := m.client.FindByName("virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Infof("Get vmi %s: %v", podName, err)
		return nil
	}
	return obj.(*types.VirtualMachineInterface)
}

// LocateInterface returns the VMI corresponding to a Pod, creating it if required
func (m *InstanceManager) LocateInterface(
	network *types.VirtualNetwork, instance *types.VirtualMachine) *types.VirtualMachineInterface {
	tenant := instance.GetFQName()[len(instance.GetFQName())-2]
	fqn := interfaceFQName(m.config.DefaultDomain, tenant, instance.GetName())

	obj, err := m.client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))

	if err == nil {
		nic := obj.(*types.VirtualMachineInterface)
		// TODO(prm): ensure network is as expected, else update.
		return nic
	}

	nic := new(types.VirtualMachineInterface)
	nic.SetFQName("project", fqn)
	nic.AddVirtualMachine(instance)
	if network != nil {
		nic.AddVirtualNetwork(network)
	}
	err = m.client.Create(nic)
	if err != nil {
		glog.Errorf("Create interface %s: %v", instance.GetName(), err)
		return nil
	}
	obj, err = m.client.FindByUuid(nic.GetType(), nic.GetUuid())
	if err != nil {
		glog.Errorf("Get vmi %s: %v", nic.GetUuid(), err)
		return nil
	}
	return obj.(*types.VirtualMachineInterface)
}

// ReleaseInterface frees the VMI corresponding to a Pod.
func (m *InstanceManager) ReleaseInterface(tenant, podName string) {
	fqn := interfaceFQName(m.config.DefaultDomain, tenant, podName)
	obj, err := m.client.FindByName("virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("Get vmi %s: %v", strings.Join(fqn, ":"), err)
		return
	}
	vmi := obj.(*types.VirtualMachineInterface)
	refs, err := vmi.GetFloatingIpBackRefs()
	if err == nil {
		for _, ref := range refs {
			fip, err := types.FloatingIpByUuid(m.client, ref.Uuid)
			if err != nil {
				glog.Errorf("Get floating-ip %s: %v", ref.Uuid, err)
				continue
			}
			fip.DeleteVirtualMachineInterface(vmi.GetUuid())
			err = m.client.Update(fip)
			if err != nil {
				glog.Errorf("Remove floating-ip reference %s: %v", ref.Uuid, err)
			}
		}
	} else {
		glog.Errorf("Get %s floating-ip back refs: %v", podName, err)
	}
	err = m.client.Delete(obj)
	if err != nil {
		glog.Errorf("Delete vmi %s: %v", obj.GetUuid(), err)
	}
}

func makeInstanceIPName(tenant, nicName string) string {
	return tenant + "_" + nicName
}

// LocateInstanceIP returns an InstanceIp object for a Pod, allocating one if required.
// Pods have unique IP addresses in the PrivateSubnet range.
func (m *InstanceManager) LocateInstanceIP(
	network *types.VirtualNetwork, instanceUID string, nic *types.VirtualMachineInterface) *types.InstanceIp {
	tenant := nic.GetFQName()[len(nic.GetFQName())-2]
	name := makeInstanceIPName(tenant, nic.GetName())
	obj, err := m.client.FindByName("instance-ip", name)
	if err == nil {
		// TODO(prm): ensure that attributes are as expected
		return obj.(*types.InstanceIp)
	}

	address, err := m.allocator.LocateIPAddress(instanceUID)
	if err != nil {
		return nil
	}

	// Create InstanceIp
	ipObj := new(types.InstanceIp)
	ipObj.SetName(name)
	ipObj.AddVirtualNetwork(network)
	ipObj.AddVirtualMachineInterface(nic)
	ipObj.SetInstanceIpAddress(address)
	ipObj.SetInstanceIpMode("active-active")
	err = m.client.Create(ipObj)
	if err != nil {
		glog.Errorf("Create instance-ip %s: %v", nic.GetName(), err)
		return nil
	}
	obj, err = m.client.FindByUuid(ipObj.GetType(), ipObj.GetUuid())
	if err != nil {
		glog.Errorf("Get instance-ip %s: %v", ipObj.GetUuid(), err)
		return nil
	}
	return ipObj
}

// ReleaseInstanceIP frees the IntanceIp object associated with a Pod.
func (m *InstanceManager) ReleaseInstanceIP(tenant, nicName, instanceUID string) {
	name := makeInstanceIPName(tenant, nicName)
	uid, err := m.client.UuidByName("instance-ip", name)
	if err != nil {
		glog.Errorf("Get instance-ip %s: %v", name, err)
		return
	}
	err = m.client.DeleteByUuid("instance-ip", uid)
	if err != nil {
		glog.Errorf("Delete instance-ip %s: %v", uid, err)
	}

	m.allocator.ReleaseIPAddress(instanceUID)
}

// AttachFloatingIP associates the VMI with a service or Public FloatingIp.
func (m *InstanceManager) AttachFloatingIP(podName, projectName string, floatingIP *types.FloatingIp) {

	fqn := []string{m.config.DefaultDomain, projectName, podName}
	obj, err := m.client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("GET vmi %s: %v", podName, err)
		return
	}

	vmi := obj.(*types.VirtualMachineInterface)

	refs, err := floatingIP.GetVirtualMachineInterfaceRefs()
	if err != nil {
		glog.Errorf("GET floating-ip %s: %v", floatingIP.GetUuid(), err)
		return
	}
	for _, ref := range refs {
		if ref.Uuid == vmi.GetUuid() {
			return
		}
	}

	floatingIP.AddVirtualMachineInterface(vmi)
	err = m.client.Update(floatingIP)
	if err != nil {
		glog.Errorf("Update floating-ip %s: %v", podName, err)
	}
}
