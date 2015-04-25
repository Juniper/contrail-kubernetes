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

package app

import (
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/api"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/client/cache"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/controller/framework"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
	"github.com/golang/glog"

	"github.com/Juniper/contrail-kubernetes/pkg/network"
)

type NetworkManager struct {
	Client     *client.Client
	Controller network.NetworkController

	ResyncPeriod time.Duration

	PodStore    cache.Store
	PodInformer *framework.Controller

	NamespaceStore    cache.Store
	NamespaceInformer *framework.Controller

	RCStore    cache.Store
	RCInformer *framework.Controller

	ServiceStore    cache.Store
	ServiceInformer *framework.Controller

	Shutdown chan struct{}
}

func NewNetworkManager() *NetworkManager {
	config := &client.Config{
		Host: "http://localhost:8080",
	}
	manager := new(NetworkManager)
	var err error
	manager.Client, err = client.New(config)
	if err != nil {
		glog.Fatalf("Invalid API configuratin: %v", err)
	}

	manager.Controller = network.NewNetworkFactory(manager.Client).Create()
	manager.Shutdown = make(chan struct{})
	manager.ResyncPeriod = time.Minute

	manager.PodStore, manager.PodInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			manager.Client,
			string(api.ResourcePods),
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.Pod{},
		manager.ResyncPeriod,
		framework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				manager.Controller.AddPod(obj.(*api.Pod))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				manager.Controller.UpdatePod(
					oldObj.(*api.Pod), newObj.(*api.Pod))
			},
			DeleteFunc: func(obj interface{}) {
				manager.Controller.DeletePod(obj.(*api.Pod))
			},
		},
	)
	manager.Controller.SetPodStore(&manager.PodStore)

	manager.NamespaceStore, manager.NamespaceInformer =
		framework.NewInformer(
			cache.NewListWatchFromClient(
				manager.Client,
				"namespaces",
				api.NamespaceAll,
				fields.Everything(),
			),
			&api.Namespace{},
			manager.ResyncPeriod,
			framework.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					manager.Controller.AddNamespace(
						obj.(*api.Namespace))
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					manager.Controller.UpdateNamespace(
						oldObj.(*api.Namespace),
						newObj.(*api.Namespace))
				},
				DeleteFunc: func(obj interface{}) {
					manager.Controller.DeleteNamespace(
						obj.(*api.Namespace))
				},
			},
		)
	manager.Controller.SetNamespaceStore(&manager.NamespaceStore)

	manager.RCStore, manager.RCInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			manager.Client,
			string(api.ResourceReplicationControllers),
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.ReplicationController{},
		manager.ResyncPeriod,
		framework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				manager.Controller.AddReplicationController(
					obj.(*api.ReplicationController))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				manager.Controller.UpdateReplicationController(
					oldObj.(*api.ReplicationController),
					newObj.(*api.ReplicationController))
			},
			DeleteFunc: func(obj interface{}) {
				manager.Controller.DeleteReplicationController(
					obj.(*api.ReplicationController))
			},
		},
	)
	manager.Controller.SetReplicationControllerStore(&manager.RCStore)

	manager.ServiceStore, manager.ServiceInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			manager.Client,
			string(api.ResourceServices),
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.Service{},
		manager.ResyncPeriod,
		framework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				manager.Controller.AddService(
					obj.(*api.Service))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				manager.Controller.UpdateService(
					oldObj.(*api.Service),
					newObj.(*api.Service))
			},
			DeleteFunc: func(obj interface{}) {
				manager.Controller.DeleteService(
					obj.(*api.Service))
			},
		},
	)
	manager.Controller.SetServiceStore(&manager.ServiceStore)

	return manager
}

func (m *NetworkManager) Run(_ []string) error {
	go m.PodInformer.Run(m.Shutdown)
	go m.NamespaceInformer.Run(m.Shutdown)
	go m.RCInformer.Run(m.Shutdown)
	go m.ServiceInformer.Run(m.Shutdown)
	select {}
}
