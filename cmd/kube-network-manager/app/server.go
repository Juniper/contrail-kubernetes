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
	"io"
	"os"
	"time"

	"github.com/golang/glog"
	flag "github.com/spf13/pflag"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/cache"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/client/unversioned/clientcmd"
	"k8s.io/kubernetes/pkg/controller/framework"
	"k8s.io/kubernetes/pkg/fields"

	"github.com/Juniper/contrail-kubernetes/pkg/network"
)

const (
	resyncTimeDefault     = time.Duration(5) * time.Minute
	clusterIPRangeDefault = "10.254.0.0/16"
)

// NetworkManager is the main class for the network manager process
type NetworkManager struct {
	ConfigFile string
	config     network.Config

	Client     *client.Client
	Controller network.Controller

	PodStore    cache.Store
	PodInformer *framework.Controller

	NamespaceStore    cache.Store
	NamespaceInformer *framework.Controller

	ServiceStore    cache.Store
	ServiceInformer *framework.Controller

	Shutdown chan struct{}
}

// NewNetworkManager allocates and initializes a NetworkManager
func NewNetworkManager() *NetworkManager {
	manager := new(NetworkManager)
	manager.config = network.Config{
		ResyncPeriod:   resyncTimeDefault,
		ClusterIPRange: clusterIPRangeDefault,
	}
	manager.Shutdown = make(chan struct{})
	return manager
}

// AddFlags adds command line flags specific to the implementation.
func (m *NetworkManager) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&m.ConfigFile, "config-file", "/etc/kubernetes/network.conf",
		"Network manager configuration")
	// DEPRECATED
	fs.StringVar(&m.config.KubeURL, "master", m.config.KubeURL,
		"Kubernetes API endpoint")
}

func (m *NetworkManager) parseConfig() io.ReadCloser {
	if m.ConfigFile == "" {
		return nil
	}
	file, err := os.Open(m.ConfigFile)
	if err != nil {
		glog.Warning(err)
		return nil
	}

	err = network.ReadConfiguration(file, &m.config)
	if err != nil {
		glog.Error(err)
	}

	_, err = file.Seek(0, 0)
	if err != nil {
		glog.Error(err)
	}

	return file
}

func (m *NetworkManager) init(args []string) {
	configFile := m.parseConfig()
	defer func() {
		if configFile != nil {
			configFile.Close()
		}
	}()

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if m.config.KubeConfig != "" {
		loadingRules.ExplicitPath = m.config.KubeConfig
	}
	configOverrides := &clientcmd.ConfigOverrides{}
	if m.config.KubeURL != "" {
		configOverrides.ClusterInfo.Server = m.config.KubeURL
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		glog.Fatal(err)
	}
	m.Client, err = client.New(config)
	if err != nil {
		glog.Fatalf("Invalid API configuratin: %v", err)
	}

	m.Controller = network.NewFactory().Create(m.Client, args)
	m.Controller.Init(&m.config, configFile)
}

func (m *NetworkManager) start(args []string) {
	m.init(args)

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
	m.Controller.SetServiceStore(m.ServiceStore)
}

// Run starts the NetworkManager and implements the main forever loop.
func (m *NetworkManager) Run(args []string) error {
	m.start(args)
	go m.PodInformer.Run(m.Shutdown)
	go m.NamespaceInformer.Run(m.Shutdown)
	go m.ServiceInformer.Run(m.Shutdown)
	go m.Controller.Run(m.Shutdown)
	select {}
}
