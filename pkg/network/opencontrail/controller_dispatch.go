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
	"reflect"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
)

func EqualTags(m1, m2 map[string]string, tags []string) bool {
	if m1 == nil {
		return m2 == nil
	}
	for _, tag := range tags {
		if m1[tag] != m2[tag] {
			return false
		}
	}
	return true
}

// IgnorePod returns true if this pod should not be managed by OpenContrail.
// Pods that use host networking on kubelet static pods fall into this category.
func IgnorePod(pod *api.Pod) bool {
	context := pod.Spec.SecurityContext
	if context != nil && context.HostNetwork {
		return true
	}

	if value, ok := pod.Annotations[kubetypes.ConfigMirrorAnnotationKey]; ok && value == kubetypes.MirrorType {
		return true
	}
	return false
}

func (c *Controller) AddPod(pod *api.Pod) {
	if IgnorePod(pod) {
		return
	}
	c.eventChannel <- notification{evAddPod, pod}
}

func (c *Controller) podAnnotationsCheck(pod *api.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	data, ok := pod.Annotations[MetadataAnnotationTag]
	if !ok {
		return false
	}

	var state InstanceMetadata
	err := json.Unmarshal([]byte(data), &state)
	if err != nil {
		return false
	}

	nic := c.instanceMgr.LookupInterface(pod.Namespace, pod.Name)
	if nic == nil || nic.GetUuid() != state.Uuid {
		return false
	}
	return true
}

func (c *Controller) UpdatePod(oldPod, newPod *api.Pod) {
	if IgnorePod(newPod) {
		if !IgnorePod(oldPod) {
			c.eventChannel <- notification{evDeletePod, oldPod}
		}
		return
	}

	watchTags := []string{
		c.config.NetworkTag,
		c.config.NetworkAccessTag,
	}
	update := false
	if !c.podAnnotationsCheck(newPod) {
		glog.V(3).Infof("Pod %s: annotations not current", newPod.Name)
		update = true
	} else if !EqualTags(oldPod.Labels, newPod.Labels, watchTags) {
		glog.V(3).Infof("Pod %s: tags have changed", newPod.Name)
		update = true
	}
	if update {
		c.eventChannel <- notification{evUpdatePod, newPod}
	}
}

func (c *Controller) DeletePod(pod *api.Pod) {
	c.eventChannel <- notification{evDeletePod, pod}
}

func (c *Controller) AddService(service *api.Service) {
	if len(service.Spec.Selector) == 0 {
		return
	}

	c.eventChannel <- notification{evAddService, service}
}

func (c *Controller) UpdateService(oldObj, newObj *api.Service) {
	update := false

	nLabel, nExists := newObj.Labels[c.config.NetworkTag]
	oLabel, oExists := oldObj.Labels[c.config.NetworkTag]

	if nExists != oExists || (nExists && nLabel != oLabel) {
		glog.V(3).Infof("Service %s: network-tag changed", newObj.Name)
		c.eventChannel <- notification{evDeleteService, oldObj}
		update = true
	} else if !reflect.DeepEqual(newObj.Spec.Selector, oldObj.Spec.Selector) {
		glog.V(3).Infof("Service %s: selector changed", newObj.Name)
		update = true
	} else if len(newObj.Spec.Selector) == 0 {
		return
	}

	if newObj.Spec.ClusterIP != oldObj.Spec.ClusterIP {
		glog.V(3).Infof("Service %s: clusterIP changed", newObj.Name)
		update = true
	}
	if !reflect.DeepEqual(newObj.Spec.ExternalIPs, oldObj.Spec.ExternalIPs) {
		glog.V(3).Infof("Service %s: ExternalIPs changed", newObj.Name)
		update = true
	}
	if newObj.Spec.Type != oldObj.Spec.Type {
		update = true
		glog.V(3).Infof("Service %s: Type changed", newObj.Name)
	} else if newObj.Spec.Type == api.ServiceTypeLoadBalancer && len(newObj.Status.LoadBalancer.Ingress) == 0 {
		update = true
		glog.V(3).Infof("Service %s: no load balancer status", newObj.Name)
	}
	if update {
		c.eventChannel <- notification{evUpdateService, newObj}
	}
}

func (c *Controller) DeleteService(service *api.Service) {
	c.eventChannel <- notification{evDeleteService, service}
}

func (c *Controller) AddNamespace(namespace *api.Namespace) {
	c.eventChannel <- notification{evAddNamespace, namespace}
}

func (c *Controller) UpdateNamespace(oldObj, newObj *api.Namespace) {
}

func (c *Controller) DeleteNamespace(namespace *api.Namespace) {
	c.eventChannel <- notification{evDeleteNamespace, namespace}
}

func (c *Controller) AddReplicationController(rc *api.ReplicationController) {
}

func (c *Controller) UpdateReplicationController(oldObj, newObj *api.ReplicationController) {
}

func (c *Controller) DeleteReplicationController(rc *api.ReplicationController) {
}
