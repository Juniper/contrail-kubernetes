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
	"fmt"
	"testing"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/Juniper/contrail-go-api"
	"github.com/Juniper/contrail-go-api/types"

	contrail_mocks "github.com/Juniper/contrail-go-api/mocks"
)

type FloatingIpInterceptor struct {
	count int
}

func (i *FloatingIpInterceptor) Put(ptr contrail.IObject) {
}

func (i *FloatingIpInterceptor) Get(ptr contrail.IObject) {
	fip := ptr.(*types.FloatingIp)
	if fip.GetFloatingIpAddress() == "" {
		i.count += 1
		fip.SetFloatingIpAddress(fmt.Sprintf("100.64.%d.%d", i.count/256, i.count&0xff))
	}
}

func TestNetworkLocate(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()

	config := new(Config)
	config.PublicNetwork = "default-domain:default-project:Public"
	netman := NewNetworkManager(client, config)

	project := new(types.Project)
	project.SetUuid(uuid.New())
	project.SetFQName("", []string{DefaultDomain, "p1"})
	client.Create(project)

	network, err := netman.LocateNetwork("p1", "n1", "10.0.1.0/24")
	assert.NoError(t, err, "LocateNetwork")

	n2, err := netman.LocateNetwork("p1", "n1", "10.0.1.0/24")
	assert.NoError(t, err, "LocateNetwork -- exists")
	assert.Equal(t, network, n2)
}
