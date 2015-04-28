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

type InstanceManager struct {
	client    *contrail.Client
	allocator *AddressAllocator
}

func NewInstanceManager(client *contrail.Client, allocator *AddressAllocator) *InstanceManager {
	manager := new(InstanceManager)
	manager.client = client
	manager.allocator = allocator
	return manager
}

func instanceFQName(namespace, podName string) []string {
	fqn := []string{DefaultDomain, namespace, podName}
	return fqn
}

func (m *InstanceManager) LocateInstance(namespace, podName, uid string) *types.VirtualMachine {
	obj, err := m.client.FindByUuid("virtual-machine", string(uid))
	if err == nil {
		return obj.(*types.VirtualMachine)
	}

	instance := new(types.VirtualMachine)
	instance.SetFQName("project", instanceFQName(namespace, podName))
	instance.SetUuid(string(uid))
	err = m.client.Create(instance)
	if err != nil {
		glog.Errorf("Create %s: %v", podName)
		return nil
	}
	return instance
}

func (m *InstanceManager) DeleteInstance(uid string) error {
	err := m.client.DeleteByUuid("virtual-machine", uid)
	return err
}

func interfaceFQName(namespace, podName string) []string {
	fqn := []string{DefaultDomain, namespace, podName}
	return fqn
}

func (m *InstanceManager) LookupInterface(namespace, podName string) *types.VirtualMachineInterface {
	fqn := interfaceFQName(namespace, podName)
	obj, err := m.client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Infof("Get vmi %s: %v", podName, err)
		return nil
	}
	return obj.(*types.VirtualMachineInterface)
}

func (m *InstanceManager) LocateInterface(
	network *types.VirtualNetwork, instance *types.VirtualMachine) *types.VirtualMachineInterface {
	namespace := instance.GetFQName()[len(instance.GetFQName())-2]
	fqn := interfaceFQName(namespace, instance.GetName())

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
	return nic
}

func (m *InstanceManager) ReleaseInterface(namespace, podName string) {
	fqn := interfaceFQName(namespace, podName)
	uid, err := m.client.UuidByName("virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("Get vmi %s: %v", strings.Join(fqn, ":"), err)
		return
	}
	err = m.client.DeleteByUuid("virtual-machine-interface", uid)
	if err != nil {
		glog.Errorf("Delete vmi %s: %v", uid, err)
	}
}

func makeInstanceIpFQName(namespace, nicName string) []string {
	return []string{DefaultDomain, namespace, nicName}
}

func (m *InstanceManager) LocateInstanceIp(
	network *types.VirtualNetwork, instanceUID string, nic *types.VirtualMachineInterface) *types.InstanceIp {
	namespace := nic.GetFQName()[len(nic.GetFQName())-2]
	fqn := makeInstanceIpFQName(namespace, nic.GetName())
	obj, err := m.client.FindByName("instance-ip", strings.Join(fqn, ":"))
	if err == nil {
		// TODO(prm): ensure that attributes are as expected
		return obj.(*types.InstanceIp)
	}

	address, err := m.allocator.LocateIpAddress(instanceUID)
	if err != nil {
		return nil
	}

	// Create InstanceIp
	ipObj := new(types.InstanceIp)
	ipObj.SetFQName("", fqn)
	ipObj.AddVirtualNetwork(network)
	ipObj.AddVirtualMachineInterface(nic)
	ipObj.SetInstanceIpAddress(address)
	err = m.client.Create(ipObj)
	if err != nil {
		glog.Errorf("Create instance-ip %s: %v", nic.GetName())
		return nil
	}
	obj, err = m.client.FindByUuid(ipObj.GetType(), ipObj.GetUuid())
	if err != nil {
		glog.Errorf("Get instance-ip %s: %v", ipObj.GetUuid())
		return nil
	}
	return ipObj
}

func (m *InstanceManager) ReleaseInstanceIp(namespace, nicName, instanceUID string) {
	fqn := makeInstanceIpFQName(namespace, nicName)
	uid, err := m.client.UuidByName("instance-ip", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("Get instance-ip %s: %v", strings.Join(fqn, ":"), err)
		return
	}
	err = m.client.DeleteByUuid("instance-ip", uid)
	if err != nil {
		glog.Errorf("Delete instance-ip %s: %v", uid, err)
	}

	m.allocator.ReleaseIpAddress(instanceUID)
}

func (m *InstanceManager) AttachFloatingIp(
	podName, projectName string, floatingIp *types.FloatingIp) {

	fqn := AppendConst(strings.Split(projectName, ":"), podName)
	obj, err := m.client.FindByName(
		"virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("GET vmi %s: %v", podName, err)
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
	err = m.client.Update(floatingIp)
	if err != nil {
		glog.Errorf("Update floating-ip %s: %v", podName, err)
	}
}
