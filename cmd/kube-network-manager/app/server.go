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

	"github.com/golang/glog"
	flag "github.com/spf13/pflag"

	"k8s.io/kubernetes/pkg/api"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/client/unversioned/cache"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/fields"

	"github.com/Juniper/contrail-kubernetes/pkg/network"
)

type Config struct {
	KubeUrl      string
	ResyncPeriod time.Duration
}

type NetworkManager struct {
	config Config

	Client     *client.Client
	Controller network.NetworkController

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
	manager := new(NetworkManager)
	manager.config = Config{
		KubeUrl:      "http://localhost:8080",
		ResyncPeriod: time.Minute,
	}
	manager.Shutdown = make(chan struct{})
	return manager
}

func (m *NetworkManager) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&m.config.KubeUrl, "master", m.config.KubeUrl,
		"Kubernetes API endpoint")
}

func (m *NetworkManager) start(args []string) {
	config := &client.Config{
		Host: m.config.KubeUrl,
	}
	var err error
	m.Client, err = client.New(config)
	if err != nil {
		glog.Fatalf("Invalid API configuratin: %v", err)
	}

	m.Controller = network.NewNetworkFactory().Create(m.Client, args)

	m.PodStore, m.PodInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			m.Client,
			string(api.ResourcePods),
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.Pod{},
		m.config.ResyncPeriod,
		framework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				m.Controller.AddPod(obj.(*api.Pod))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				m.Controller.UpdatePod(
					oldObj.(*api.Pod), newObj.(*api.Pod))
			},
			DeleteFunc: func(obj interface{}) {
				if pod, ok := obj.(*api.Pod); ok {
					m.Controller.DeletePod(pod)
				}
			},
		},
	)

	m.NamespaceStore, m.NamespaceInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			m.Client,
			"namespaces",
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.Namespace{},
		m.config.ResyncPeriod,
		framework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				m.Controller.AddNamespace(
					obj.(*api.Namespace))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				m.Controller.UpdateNamespace(
					oldObj.(*api.Namespace),
					newObj.(*api.Namespace))
			},
			DeleteFunc: func(obj interface{}) {
				if namespace, ok := obj.(*api.Namespace); ok {
					m.Controller.DeleteNamespace(namespace)
				}
			},
		},
	)

	m.RCStore, m.RCInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			m.Client,
			string(api.ResourceReplicationControllers),
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.ReplicationController{},
		m.config.ResyncPeriod,
		framework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				m.Controller.AddReplicationController(
					obj.(*api.ReplicationController))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				m.Controller.UpdateReplicationController(
					oldObj.(*api.ReplicationController),
					newObj.(*api.ReplicationController))
			},
			DeleteFunc: func(obj interface{}) {
				if rc, ok := obj.(*api.ReplicationController); ok {
					m.Controller.DeleteReplicationController(rc)
				}
			},
		},
	)

	m.ServiceStore, m.ServiceInformer = framework.NewInformer(
		cache.NewListWatchFromClient(
			m.Client,
			string(api.ResourceServices),
			api.NamespaceAll,
			fields.Everything(),
		),
		&api.Service{},
		m.config.ResyncPeriod,
		framework.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				m.Controller.AddService(
					obj.(*api.Service))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				m.Controller.UpdateService(
					oldObj.(*api.Service),
					newObj.(*api.Service))
			},
			DeleteFunc: func(obj interface{}) {
				if service, ok := obj.(*api.Service); ok {
					m.Controller.DeleteService(service)
				}
			},
		},
	)

	m.Controller.SetPodStore(m.PodStore)
	m.Controller.SetNamespaceStore(m.NamespaceStore)
	m.Controller.SetReplicationControllerStore(m.RCStore)
	m.Controller.SetServiceStore(m.ServiceStore)
}

func (m *NetworkManager) Run(args []string) error {
	m.start(args)
	go m.PodInformer.Run(m.Shutdown)
	go m.NamespaceInformer.Run(m.Shutdown)
	go m.RCInformer.Run(m.Shutdown)
	go m.ServiceInformer.Run(m.Shutdown)
	go m.Controller.Run(m.Shutdown)
	select {}
}
