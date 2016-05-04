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
	"github.com/Juniper/contrail-go-api/types"
)

// NamespaceManager maps Namespaces in the k8s API to Projects in the contrail API.
type NamespaceManager struct {
	client contrail.ApiClient
	config *Config
}

// NewNamespaceManager allocates and initializes a NamespaceManager
func NewNamespaceManager(client contrail.ApiClient, config *Config) *NamespaceManager {
	manager := new(NamespaceManager)
	manager.client = client
	manager.config = config
	return manager
}

// LookupNamespace returns the Project corresponding to a Namespace, if it exists
func (m *NamespaceManager) LookupNamespace(name string) *types.Project {
	fqn := []string{m.config.DefaultDomain, name}

	obj, err := m.client.FindByName("project", strings.Join(fqn, ":"))
	if err != nil {
		return nil
	}
	return obj.(*types.Project)
}

// LocateNamespace returns the Project corresponding to a Namespace, allocating one if required
func (m *NamespaceManager) LocateNamespace(name, uid string) *types.Project {
	fqn := []string{m.config.DefaultDomain, name}

	obj, err := m.client.FindByName("project", strings.Join(fqn, ":"))
	if err == nil {
		return obj.(*types.Project)
	}
	project := new(types.Project)
	project.SetFQName("domain", fqn)
	project.SetUuid(uid)
	err = m.client.Create(project)
	if err != nil {
		glog.Errorf("Create project %s: %v", name, err)
	}
	return project
}

// DeleteNamespace deletes the Project corresponding to the Namespace
func (m *NamespaceManager) DeleteNamespace(name string) error {
	fqn := []string{m.config.DefaultDomain, name}

	obj, err := m.client.FindByName("project", strings.Join(fqn, ":"))
	if err != nil {
		return err
	}

	m.client.Delete(obj)
	return nil
}
