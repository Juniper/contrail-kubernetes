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

import ()

const (
	DefaultDomain  = "default-domain"
	DefaultProject = "default-domain:default-project"
)

type Config struct {
	ApiAddress string
	ApiPort    int

	DefaultProject string
	PublicNetwork  string
	PublicSubnet   string
	PrivateSubnet  string
	// aka PortalNet
	ServiceSubnet string

	NetworkTag       string
	NetworkAccessTag string
}

func (c *Config) Defaults() {
	c.ApiAddress = "localost"
	c.ApiPort = 8082

	c.NetworkTag = "name"
	c.NetworkAccessTag = "uses"
}

func (c *Config) Parse() {

}

// // TODO(prm): use configuration file to modify parameters
// const (
// 	ApiAddress     = "localhost"
// 	ApiPort        = 8082
// 	DefaultDomain  = "default-domain"
// 	DefaultProject = "default-domain:default-project"
// 	PublicNetwork  = "default-domain:default-project:Public"
// 	PublicSubnet   = "10.1.0.0/16"
// 	PrivateSubnet  = "10.0.0.0/16"
// 	// TODO: read from kubernetes configuration file.
// 	ServiceSubnet = "10.254.0.0/16"
// )
