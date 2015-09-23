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
	"testing"

	"github.com/stretchr/testify/assert"

	contrail_mocks "github.com/Juniper/contrail-go-api/mocks"
	"github.com/Juniper/contrail-go-api/types"
)

func TestPurgeServiceList(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()

	config := NewConfig()
	networkMgr := NewNetworkManager(client, config)
	serviceMgr := NewServiceManager(client, config, networkMgr)

	netnsProject := new(types.Project)
	netnsProject.SetFQName("", []string{"default-domain", "testns"})
	client.Create(netnsProject)

	globalProject := new(types.Project)
	globalProject.SetFQName("", []string{"default-domain", "global"})
	client.Create(globalProject)

	network, err := networkMgr.LocateNetwork("testns", "client", config.PrivateSubnet)

	services := []string{
		"testns/s1",
		"testns/s2",
		"global/s3",
		"global/s4",
	}

	for _, svc := range services {
		parts := strings.Split(svc, "/")
		namespace := parts[0]
		svcName := parts[1]
		err := serviceMgr.Create(namespace, svcName)
		if err != nil {
			t.Error(err)
			continue
		}
		err = serviceMgr.Connect(namespace, svcName, network)
		if err != nil {
			t.Error(err)
		}
	}

	serviceList := MakeServiceIdList()
	serviceList.Add("testns", "s1")
	serviceList.Add("global", "s3")

	err = serviceMgr.PurgeStalePolicyRefs(network, serviceList,
		func(namespace, name string) bool {
			return true
		})
	if err != nil {
		t.Fatal(err)
	}

	refs, err := network.GetNetworkPolicyRefs()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != len(serviceList) {
		t.Errorf("expected %d policy refs, got %d", len(serviceList), len(refs))
	}
	actual := make([]string, 0)
	for _, ref := range refs {
		actual = append(actual, ref.To[1]+"/"+ref.To[2])
	}
	assert.EqualValues(t, []string{"testns/s1", "global/s3"}, actual)
}
