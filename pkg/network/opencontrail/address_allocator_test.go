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
	"testing"

	"github.com/golang/glog"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"

	contrail_mocks "github.com/Juniper/contrail-go-api/mocks"
	"github.com/Juniper/contrail-go-api/types"
)

func TestAllocator(t *testing.T) {
	client := new(contrail_mocks.ApiClient)
	client.Init()
	client.AddInterceptor("instance-ip", &ipInterceptor{})

	allocator := NewAddressAllocator(client, NewConfig())

	id := uuid.New()
	addr, err := allocator.LocateIPAddress(id)
	assert.NoError(t, err)
	assert.Equal(t, "10.254.0.1", addr)

	ipObj, err := types.InstanceIpByName(client, id)
	assert.NoError(t, err)
	glog.Infof(ipObj.GetInstanceIpAddress())

	allocator.ReleaseIPAddress(id)
	_, err = types.InstanceIpByName(client, id)
	assert.Error(t, err)
}
