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
	flag "github.com/spf13/pflag"
)

const (
	DefaultDomain = "default-domain"
)

type Config struct {
	ApiAddress string
	ApiPort    int

	DefaultProject string
	PublicNetwork  string

	PublicSubnet  string
	PrivateSubnet string
	ServiceSubnet string

	NetworkTag       string
	NetworkAccessTag string
}

func NewConfig() *Config {
	config := &Config{
		ApiAddress:       "localhost",
		ApiPort:          8082,
		DefaultProject:   "default-domain:default-project",
		PublicNetwork:    "default-domain:default-project:Public",
		PrivateSubnet:    "10.10.0.0/16",
		ServiceSubnet:    "10.247.0.0/16",
		PublicSubnet:     "10.1.0.0/16",
		NetworkTag:       "name",
		NetworkAccessTag: "uses",
	}
	return config
}

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
