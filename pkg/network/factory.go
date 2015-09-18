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

package network

import (
	client "k8s.io/kubernetes/pkg/client/unversioned"
)

type Allocator func(*client.Client, []string) NetworkController

var (
	allocatorMap map[string]Allocator
)

func Register(networkImpl string, allocFn Allocator) {
	if allocatorMap == nil {
		allocatorMap = make(map[string]Allocator, 0)
	}
	allocatorMap[networkImpl] = allocFn
}

// Placeholder class that constructs a NetworkController
type NetworkFactory struct {
}

func NewNetworkFactory() *NetworkFactory {
	factory := new(NetworkFactory)
	return factory
}

func (f *NetworkFactory) Create(client *client.Client, args []string) NetworkController {
	// TODO(prm): read configuration in order to select plugin.
	if alloc, ok := allocatorMap["opencontrail"]; ok {
		return alloc(client, args)
	}
	return nil
}
