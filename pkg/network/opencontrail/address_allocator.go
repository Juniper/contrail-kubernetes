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
	"github.com/Juniper/contrail-go-api/config"
	"github.com/Juniper/contrail-go-api/types"
)

// AddressAllocator defines the interface between the controller and address allocation.
type AddressAllocator interface {
	LocateIPAddress(uid string) (string, error)
	ReleaseIPAddress(uid string)
}

// addressAllocatorImpl uses the contrail API to allocate an unique address for each Pod.
type addressAllocatorImpl struct {
	client        contrail.ApiClient
	network       *types.VirtualNetwork
	privateSubnet string
}

const (
	// AddressAllocationNetwork is the network used to allocate IP addresses.
	// This network is used only to allocate instance-ip objects.
	AddressAllocationNetwork = "default-domain:default-project:addr-alloc"
)

// NewAddressAllocator returns the default AddressAllocator implementation.
func NewAddressAllocator(client contrail.ApiClient, config *Config) AddressAllocator {
	allocator := new(addressAllocatorImpl)
	allocator.client = client
	allocator.privateSubnet = config.PrivateSubnet
	allocator.initializeAllocator()
	return allocator
}

func (a *addressAllocatorImpl) initializeAllocator() {
	obj, err := a.client.FindByName("virtual-network", AddressAllocationNetwork)
	if err == nil {
		a.network = obj.(*types.VirtualNetwork)
		return
	}

	fqn := strings.Split(AddressAllocationNetwork, ":")
	parent := strings.Join(fqn[0:len(fqn)-1], ":")
	projectID, err := a.client.UuidByName("project", parent)
	if err != nil {
		glog.Fatalf("%s: %v", parent, err)
	}
	netID, err := config.CreateNetworkWithSubnet(
		a.client, projectID, fqn[len(fqn)-1], a.privateSubnet)
	if err != nil {
		glog.Fatalf("%s: %v", parent, err)
	}
	glog.Infof("Created network %s", AddressAllocationNetwork)
	obj, err = a.client.FindByUuid("virtual-network", netID)
	if err != nil {
		glog.Fatalf("Get virtual-network %s: %v", netID, err)
	}
	a.network = obj.(*types.VirtualNetwork)
}

func (a *addressAllocatorImpl) allocateIPAddress(uid string) (contrail.IObject, error) {
	ipObj := new(types.InstanceIp)
	ipObj.SetName(uid)
	ipObj.AddVirtualNetwork(a.network)
	err := a.client.Create(ipObj)
	if err != nil {
		glog.Errorf("Create InstanceIp %s: %v", uid, err)
		return nil, err
	}
	obj, err := a.client.FindByUuid("instance-ip", ipObj.GetUuid())
	if err != nil {
		glog.Errorf("Get InstanceIp %s: %v", uid, err)
		return nil, err
	}
	return obj, err
}

func (a *addressAllocatorImpl) LocateIPAddress(uid string) (string, error) {
	obj, err := a.client.FindByName("instance-ip", uid)
	if err != nil {
		obj, err = a.allocateIPAddress(uid)
		if err != nil {
			return "", err
		}
	}

	ipObj := obj.(*types.InstanceIp)
	return ipObj.GetInstanceIpAddress(), nil
}

func (a *addressAllocatorImpl) ReleaseIPAddress(uid string) {
	objid, err := a.client.UuidByName("instance-ip", uid)
	if err != nil {
		glog.V(1).Infof("IP address for %s: %v", uid, err)
		return
	}
	err = a.client.DeleteByUuid("instance-ip", objid)
	if err != nil {
		glog.Warningf("Delete instance-ip: %v", err)
	}
}
