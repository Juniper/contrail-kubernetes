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
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	assert := assert.New(t)
	config := NewConfig()
	assert.Equal("localhost", config.ApiAddress)
	config.Parse([]string{"--portal_net=172.12.0.0/16"})
	assert.Equal("172.12.0.0/16", config.ServiceSubnet)
	assert.Equal("localhost", config.ApiAddress)
}

func TestConfigFile(t *testing.T) {
	content := `
[DEFAULT]
service-cluster-ip-range = 10.253.0.0/16

[opencontrail]
api-server = master
network-label = k8-app
public-ip-range = 192.168.0.0/24
`
	buffer := bytes.NewBufferString(content)
	config := NewConfig()
	err := config.ReadConfiguration(nil, buffer)
	if err != nil {
		t.Fatal(err)
	}
	if config.ApiAddress != "master" {
		t.Errorf("expected master, got %s", config.ApiAddress)
	}
	if config.NetworkTag != "k8-app" {
		t.Errorf("expected k8-app, got %s", config.NetworkTag)
	}
	if config.PublicSubnet != "192.168.0.0/24" {
		t.Errorf("expected 192.168.0.0/24, got %s", config.PublicSubnet)
	}
}

func TestConfigClusterServices(t *testing.T) {
	content := `
[opencontrail]
cluster-service = kube-system/dns
cluster-service = kube-system/monitoring
`
	buffer := bytes.NewBufferString(content)
	config := NewConfig()
	err := config.ReadConfiguration(nil, buffer)
	if err != nil {
		t.Fatal(err)
	}

	if len(config.ClusterServices) != 2 {
		t.Errorf("expected 2 entries in cluster-services list, got %d", len(config.ClusterServices))
	}
	values := []string{"dns", "monitoring"}
	for i, v := range values {
		fqn := strings.Split(config.ClusterServices[i], "/")
		if fqn[len(fqn)-1] != v {
			t.Errorf("expected %s, got %s", v, fqn[len(fqn)-1])
		}
	}
}

func TestConfigGlobalNetworks(t *testing.T) {
	content := `
[opencontrail]
global-network = default-domain:default-project:Public
global-network = default-domain:default:logging
global-connect-include = "project-.*"
global-connect-exclude = "kube-system/.*"
`
	buffer := bytes.NewBufferString(content)
	config := NewConfig()
	err := config.ReadConfiguration(nil, buffer)
	if err != nil {
		t.Fatal(err)
	}

	if len(config.GlobalNetworks) != 2 {
		t.Errorf("expected 2 entries in global-network list, got %d", len(config.GlobalNetworks))
	}

	re, err := regexp.Compile(config.GlobalConnectInclude)
	if err != nil {
		t.Errorf("global-connect-include: %+v", err)
	}
	value := "project-a/default"
	if !re.Match([]byte(value)) {
		t.Errorf("expected regexp match on %s, failed", value)
	}

	re, err = regexp.Compile(config.GlobalConnectExclude)
	if err != nil {
		t.Errorf("global-connect-exclude: %+v", err)
	}
	value = "kube-system/monitoring"
	if !re.Match([]byte(value)) {
		t.Errorf("expected regexp match on %s, failed", value)
	}
}

func TestGlobalNetworkNameCheck(t *testing.T) {
	illegalNames := []string{
		"domain:project",
		"domain::name",
		"::",
	}
	for _, v := range illegalNames {
		assert.Error(t, validateColonSeparatedNetworkName(v))
	}
}
