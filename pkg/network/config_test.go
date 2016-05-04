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
	"bytes"
	"testing"
	"time"
)

func TestMaster(t *testing.T) {
	configData := `
[DEFAULT]
master = https://master:443

[opencontrail]
option = value
`
	buffer := bytes.NewBufferString(configData)
	var config Config
	err := ReadConfiguration(buffer, &config)
	if err != nil {
		t.Error(err)
	}
	if config.KubeURL != "https://master:443" {
		t.Errorf("expected https://master:443, got %s", config.KubeURL)
	}
}

func TestDuration(t *testing.T) {
	configData := `
[DEFAULT]
resync-interval = 10
`
	buffer := bytes.NewBufferString(configData)
	var config Config
	err := ReadConfiguration(buffer, &config)
	if err != nil {
		t.Error(err)
	}
	if config.ResyncPeriod != time.Duration(10)*time.Second {
		t.Errorf("expected 10s, got %s", config.ResyncPeriod.String())
	}
}

func TestBadSubnet(t *testing.T) {
	configData := `
[DEFAULT]
service-cluster-ip-range = 10
`
	buffer := bytes.NewBufferString(configData)
	var config Config
	err := ReadConfiguration(buffer, &config)
	if err == nil {
		t.Errorf("expected error")
	}
}
