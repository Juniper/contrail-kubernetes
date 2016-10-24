/*
Copyright 2016 Juniper Networks, Inc. All rights reserved.

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
	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"
)

type virtualRouterMap map[string]*types.VirtualRouter

type VirtualRouterManager struct {
	client contrail.ApiClient
	config *Config
	vrMap  virtualRouterMap
}

// Setup
func NewVirtualRouterManager(client contrail.ApiClient, config *Config) (*VirtualRouterManager, error) {
	vrMgr := new(VirtualRouterManager)
	vrMgr.vrMap = make(virtualRouterMap, 0)
	vrMgr.client = client
	vrMgr.config = config

	objects, err := client.ListDetail("virtual-router", nil)
	if err != nil {
		glog.Error(err)
		return nil, err
	}

	for _, object := range objects {
		vr := object.(*types.VirtualRouter)
		vrMgr.vrMap[vr.GetVirtualRouterIpAddress()] = vr
	}
	return vrMgr, nil
}

// Add Pod(VM) reference to VirtualRouter in Contrail Config
func (vrMgr *VirtualRouterManager) addPodRefToVirtualRouter(
	pod *api.Pod, instance *types.VirtualMachine) bool {

	if pod.Status.HostIP == "" {
		glog.Infof("HostIP is empty during pod(%s) add/update", pod.Name)
		return true
	}

	// Given HostIP, find virtual-router.
	var vr *types.VirtualRouter
	vr = vrMgr.vrMap[pod.Status.HostIP]
	if vr == nil {
		glog.Errorf("Pod(%s) added to non-exisitng Virtual-router(%s) node", pod.Name, pod.Status.HostIP)
		return false
	}

	// Update reference to virtual-machine
	err := vr.ObjectBase.ClientPtr.UpdateReference(
		&contrail.ReferenceUpdateMsg{
			vr.GetType(),
			vr.GetUuid(), "virtual-machine", instance.GetUuid(), instance.GetFQName(),
			"ADD",
			nil,
		})
	if err != nil {
		glog.Errorf("Failed to add pod(%s) to vrouter(%s): %v", pod.Name, pod.Status.HostIP, err)
		return false
	}

	glog.Infof("pod(%s) added to vRouter(%s)", pod.Name, pod.Status.HostIP)
	return true
}

// Remove Pod(VM) reference from VirtualRouter in Contrail Config
func (vrMgr *VirtualRouterManager) removePodRefFromVirtualRouter(
	pod *api.Pod, instance *types.VirtualMachine) bool {

	if pod.Status.HostIP == "" {
		glog.Warningf("HostIP is empty during pod(%s) delete", pod.Name)
		return false;
	}

	// Given HostIP, find virtual-router.
	var vr *types.VirtualRouter
	vr = vrMgr.vrMap[pod.Status.HostIP]
	if vr == nil {
		glog.Errorf("Pod(%s) removed from non-exisitng Virtual-router(%s) node", pod.Name, pod.Status.HostIP)
		return false
	}

	// Update reference to virtual-machine
	err := vr.ObjectBase.ClientPtr.UpdateReference(
		&contrail.ReferenceUpdateMsg{
			vr.GetType(),
			vr.GetUuid(), "virtual-machine", instance.GetUuid(), instance.GetFQName(),
			"DELETE",
			nil,
		})
	if err != nil {
		glog.Errorf("Failed to remove pod(%s) from vrouter(%s): %v", pod.Name, pod.Status.HostIP, err)
		return false
	}

	return true
}
