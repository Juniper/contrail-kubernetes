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
	client    contrail.ApiClient
	allocator AddressAllocator
}

func NewInstanceManager(client contrail.ApiClient, allocator AddressAllocator) *InstanceManager {
	manager := new(InstanceManager)
	manager.client = client
	manager.allocator = allocator
	return manager
}

func instanceFQName(tenant, podName string) []string {
	fqn := []string{DefaultDomain, tenant, podName}
	return fqn
}

func (m *InstanceManager) LocateInstance(tenant, podName, uid string) *types.VirtualMachine {
	obj, err := m.client.FindByUuid("virtual-machine", string(uid))
	if err == nil {
		return obj.(*types.VirtualMachine)
	}

	instance := new(types.VirtualMachine)
	instance.SetFQName("project", instanceFQName(tenant, podName))
	instance.SetUuid(uid)
	err = m.client.Create(instance)
	if err != nil {
		glog.Errorf("Create %s: %v", podName, err)
		return nil
	}
	return instance
}

func (m *InstanceManager) DeleteInstance(uid string) error {
	err := m.client.DeleteByUuid("virtual-machine", uid)
	return err
}

func interfaceFQName(tenant, podName string) []string {
	fqn := []string{DefaultDomain, tenant, podName}
	return fqn
}

func (m *InstanceManager) LookupInterface(tenant, podName string) *types.VirtualMachineInterface {
	fqn := interfaceFQName(tenant, podName)
	obj, err := m.client.FindByName("virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Infof("Get vmi %s: %v", podName, err)
		return nil
	}
	return obj.(*types.VirtualMachineInterface)
}

func (m *InstanceManager) LocateInterface(
	network *types.VirtualNetwork, instance *types.VirtualMachine) *types.VirtualMachineInterface {
	tenant := instance.GetFQName()[len(instance.GetFQName())-2]
	fqn := interfaceFQName(tenant, instance.GetName())

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

func (m *InstanceManager) ReleaseInterface(tenant, podName string) {
	fqn := interfaceFQName(tenant, podName)
	obj, err := m.client.FindByName("virtual-machine-interface", strings.Join(fqn, ":"))
	if err != nil {
		glog.Errorf("Get vmi %s: %v", strings.Join(fqn, ":"), err)
		return
	}
	vmi := obj.(*types.VirtualMachineInterface)
	refs, err := vmi.GetFloatingIpBackRefs()
	if err == nil {
		for _, ref := range refs {
			err = m.client.DeleteByUuid("floating-ip", ref.Uuid)
			if err != nil {
				glog.Errorf("Delete floating-ip %s: %v", ref.Uuid, err)
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

func makeInstanceIpName(tenant, nicName string) string {
	return tenant + "_" + nicName
}

func (m *InstanceManager) LocateInstanceIp(
	network *types.VirtualNetwork, instanceUID string, nic *types.VirtualMachineInterface) *types.InstanceIp {
	tenant := nic.GetFQName()[len(nic.GetFQName())-2]
	name := makeInstanceIpName(tenant, nic.GetName())
	obj, err := m.client.FindByName("instance-ip", name)
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
	ipObj.SetName(name)
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

func (m *InstanceManager) ReleaseInstanceIp(tenant, nicName, instanceUID string) {
	name := makeInstanceIpName(tenant, nicName)
	uid, err := m.client.UuidByName("instance-ip", name)
	if err != nil {
		glog.Errorf("Get instance-ip %s: %v", name, err)
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

	fqn := []string{DefaultDomain, projectName, podName}
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
