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
	"reflect"

	"github.com/golang/glog"

	"k8s.io/kubernetes/pkg/api"
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

func (c *Controller) AddPod(pod *api.Pod) {
	c.eventChannel <- notification{evAddPod, pod}
}

func (c *Controller) podAnnotationsCheck(pod *api.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	id, ok := pod.Annotations[MetadataAnnotationTag]
	if !ok {
		return false
	}
	nic := c.instanceMgr.LookupInterface(pod.Namespace, pod.Name)
	if nic == nil || nic.GetUuid() != id {
		return false
	}
	return true
}

func (c *Controller) UpdatePod(oldPod, newPod *api.Pod) {
	watchTags := []string{
		c.config.NetworkTag,
		c.config.NetworkAccessTag,
	}
	update := false
	if !c.podAnnotationsCheck(newPod) {
		update = true
	} else if !EqualTags(oldPod.Labels, newPod.Labels, watchTags) {
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
		update = true
	}
	if !reflect.DeepEqual(newObj.Spec.ExternalIPs, oldObj.Spec.ExternalIPs) {
		update = true
	}
	if newObj.Spec.Type != oldObj.Spec.Type {
		update = true
	} else if newObj.Spec.Type == api.ServiceTypeLoadBalancer && len(newObj.Status.LoadBalancer.Ingress) == 0 {
		update = true
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
