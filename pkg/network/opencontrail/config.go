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
	"io"
	"net"
	"regexp"
	"strings"

	flag "github.com/spf13/pflag"

	"gopkg.in/gcfg.v1"

	"github.com/Juniper/contrail-kubernetes/pkg/network"
)

const (
	DefaultServiceSubnet = "10.254.0.0/16"
)

type Config struct {
	// OpenContrail Default Domain
	DefaultDomain string `gcfg:"default-domain"`

	// OpenContrail api server address:port
	ApiAddress string `gcfg:"api-server"`
	ApiPort    int    `gcfg:"api-port"`

	// Project used for objects that are not namespace specific
	DefaultProject string `gcfg:"default-project"`
	// Network identifier for the external network
	PublicNetwork string `gcfg:"public-network"`
	// IP address range configured on the external network
	PublicSubnet string `gcfg:"public-ip-range"`
	// IP address range used to allocate Pod private IP addresses
	PrivateSubnet string `gcfg:"private-ip-range"`
	// IP address range used by the kube-apiserver to allocate ClusterIP addresses for services
	ServiceSubnet string `gcfg:"service-cluster-ip-range"`

	// Label used to create the network name used by pods and services
	NetworkTag string `gcfg:"network-label"`
	// Label used to connect pods with services
	NetworkAccessTag string `gcfg:"service-label"`

	// Networks connected to all pod networks
	GlobalNetworks []string `gcfg:"global-network"`
	// Connect networks that match this pattern to the global network list.
	GlobalConnectInclude string `gcfg:"global-connect-include"`
	// Exclude networks that match the following pattern from connecting to the global network list.
	GlobalConnectExclude string `gcfg:"global-connect-exclude"`

	// Cluster-wide service networks
	ClusterServices []string `gcfg:"cluster-service"`

	// Tenant-specific service networks that are automatically attached to tenant networks
	NamespaceServices []string `gcfg:"namespace-service"`
}

func NewConfig() *Config {
	config := &Config{
		DefaultDomain:        "default-domain",
		ApiAddress:           "localhost",
		ApiPort:              8082,
		DefaultProject:       "default-domain:default-project",
		PublicNetwork:        "default-domain:default-project:Public",
		PrivateSubnet:        "10.0.0.0/16",
		ServiceSubnet:        DefaultServiceSubnet,
		NetworkTag:           "opencontrail.org/name",
		NetworkAccessTag:     "opencontrail.org/services",
		GlobalConnectInclude: ".*",
		NamespaceServices:    []string{DefaultServiceNetworkName},
	}
	return config
}

// DEPRECATED
func (c *Config) Parse(args []string) {
	fs := flag.NewFlagSet("opencontrail", flag.ExitOnError)
	fs.StringVar(&c.ApiAddress, "contrail_api", c.ApiAddress,
		"Hostname or address for the OpenContrail API server.")
	fs.IntVar(&c.ApiPort, "contrail_port", 8082,
		"OpenContrail API port.")
	fs.StringVar(&c.PublicNetwork, "public_name", c.PublicNetwork,
		"External network name.")
	fs.StringVar(&c.PublicSubnet, "public_net", c.PublicSubnet,
		"External network subnet prefix used when provisioning the cluster.")
	fs.StringVar(&c.PrivateSubnet, "private_net", c.PrivateSubnet,
		"Address range to use for private IP addresses.")
	fs.StringVar(&c.ServiceSubnet, "portal_net", c.ServiceSubnet,
		"Address range to use for services.")
	fs.StringVar(&c.NetworkTag, "network_label", c.NetworkTag,
		"Label used to specify the network used by the resource (pod or service).")
	fs.StringVar(&c.NetworkAccessTag, "access_label", c.NetworkAccessTag,
		"Label used to determine what services this resource (pod/rc) accesses.")
	fs.Parse(args)
}

type configWrapper struct {
	Default      network.Config
	OpenContrail Config
}

func validateQualifiedNetworkName(name string) error {
	serviceName := strings.Split(name, "/")
	if len(serviceName) != 2 {
		return fmt.Errorf("Expected 'namespace/service', got \"%s\"", name)
	}
	return nil
}

func validateColonSeparatedNetworkName(name string) error {
	networkName := strings.Split(name, ":")
	if len(networkName) != 3 {
		return fmt.Errorf("Expected 'domain:project:network', got \"%s\"", name)
	}
	for _, v := range networkName {
		if v == "" {
			return fmt.Errorf("Empty element in fully qualified network name")
		}
	}
	return nil
}

func validateNamespaceService(name string) error {
	if strings.Contains(name, "/") {
		return fmt.Errorf("Namespace-specific service \"%s\": cannot contain namespace separator (\"/\")", name)
	}
	return nil
}

func (c *Config) Validate() error {
	if _, _, err := net.ParseCIDR(c.PrivateSubnet); err != nil {
		return err
	}
	if c.PublicSubnet != "" {
		if _, _, err := net.ParseCIDR(c.PublicSubnet); err != nil {
			return err
		}
	}
	if _, _, err := net.ParseCIDR(c.ServiceSubnet); err != nil {
		return err
	}

	for _, svc := range c.ClusterServices {
		err := validateQualifiedNetworkName(svc)
		if err != nil {
			return err
		}
	}

	if c.GlobalConnectInclude != "" {
		if _, err := regexp.Compile(c.GlobalConnectInclude); err != nil {
			return err
		}
	}

	if c.GlobalConnectExclude != "" {
		if _, err := regexp.Compile(c.GlobalConnectExclude); err != nil {
			return err
		}
	}

	for _, net := range c.GlobalNetworks {
		err := validateColonSeparatedNetworkName(net)
		if err != nil {
			return err
		}
	}
	for _, svc := range c.NamespaceServices {
		err := validateNamespaceService(svc)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) ReadConfiguration(global *network.Config, reader io.Reader) error {
	if global != nil && c.ServiceSubnet == DefaultServiceSubnet {
		c.ServiceSubnet = global.ClusterIpRange
	}

	if reader == nil {
		return nil
	}

	wrapper := configWrapper{OpenContrail: *c}
	if err := gcfg.ReadInto(&wrapper, reader); err != nil {
		return err
	}
	if err := wrapper.OpenContrail.Validate(); err != nil {
		return err
	}
	*c = wrapper.OpenContrail
	return nil
}
