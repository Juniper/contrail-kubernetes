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
	Client *client.Client
	Controller network.NetworkController
	PodStore cache.Store
	PodInformer *framework.Controller
	Shutdown chan struct {}
}

func NewNetworkManager() *NetworkManager {
	config := &client.Config{
		Host:	"http://localhost:8080",
	}
	manager := new(NetworkManager)
	var err error
	manager.Client, err = client.New(config)
	if err != nil {
		glog.Fatalf("Invalid API configuratin: %v", err)
	}

	manager.Controller = network.NewNetworkFactory().Create()
	manager.Shutdown = make(chan struct {})
	manager.PodStore, manager.PodInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			manager.Client,
			"pods",
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.Pod{},
		time.Minute,
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
	
	return manager
}

func (m *NetworkManager) Run(_ []string) error {
	go m.PodInformer.Run(m.Shutdown)
	select {}
}
