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

// Allocate an unique address for each Pod.
type AddressAllocator struct {
	client        *contrail.Client
	network       *types.VirtualNetwork
	privateSubnet string
}

const (
	AddressAllocationNetwork = "default-domain:default-project:addr-alloc"
)

func NewAddressAllocator(client *contrail.Client, config *Config) *AddressAllocator {
	allocator := new(AddressAllocator)
	allocator.client = client
	allocator.privateSubnet = config.PrivateSubnet
	allocator.initializeAllocator()
	return allocator
}

func (a *AddressAllocator) initializeAllocator() {
	obj, err := a.client.FindByName("virtual-network", AddressAllocationNetwork)
	if err == nil {
		a.network = obj.(*types.VirtualNetwork)
		return
	}

	fqn := strings.Split(AddressAllocationNetwork, ":")
	parent := strings.Join(fqn[0:len(fqn)-1], ":")
	projectId, err := a.client.UuidByName("project", parent)
	if err != nil {
		glog.Fatalf("%s: %v", parent, err)
	}
	_, err = config.CreateNetworkWithSubnet(
		a.client, projectId, fqn[len(fqn)-1], a.privateSubnet)
	if err != nil {
		glog.Fatalf("%s: %v", parent, err)
	}
	glog.Infof("Created network %s", AddressAllocationNetwork)
}

func (a *AddressAllocator) allocateIpAddress(uid string) (contrail.IObject, error) {
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

func (a *AddressAllocator) LocateIpAddress(uid string) (string, error) {
	obj, err := a.client.FindByName("instance-ip", uid)
	if err != nil {
		obj, err = a.allocateIpAddress(uid)
		if err != nil {
			return "", err
		}
	}

	ipObj := obj.(*types.InstanceIp)
	return ipObj.GetInstanceIpAddress(), nil
}

func (a *AddressAllocator) ReleaseIpAddress(uid string) {
	objid, err := a.client.UuidByName("instance-ip", uid)
	if err != nil {
		err = a.client.DeleteByUuid("instance-ip", objid)
		if err != nil {
			glog.Warningf("Delete instance-ip: %v", err)
		}
	}
}
