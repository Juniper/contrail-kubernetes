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
	"strconv"
	"strings"
)

type serviceID struct {
	Namespace string
	Service   string
}

type serviceIDList []serviceID

func (s *serviceIDList) Contains(namespace, service string) bool {
	for _, entry := range *s {
		if entry.Namespace == namespace && entry.Service == service {
			return true
		}
	}
	return false
}
func (s *serviceIDList) Add(namespace, service string) {
	if s.Contains(namespace, service) {
		return
	}
	*s = append(*s, serviceID{namespace, service})
}

func makeServiceIDList() serviceIDList {
	return make(serviceIDList, 0)
}

// serviceIDFromName splits a prevalidated string in the form namespace/service-name.
func serviceIDFromName(name string) (string, string) {
	tuple := strings.Split(name, "/")
	return tuple[0], tuple[1]
}

func isClusterService(c *Config, namespace, name string) bool {
	for _, svc := range c.ClusterServices {
		svcNamespace, svcName := serviceIDFromName(svc)
		if svcNamespace == namespace && svcName == name {
			return true
		}
	}
	return false
}

func appendConst(slice []string, element string) []string {
	newSlice := make([]string, len(slice), len(slice)+1)
	copy(newSlice, slice)
	return append(newSlice, element)
}

func prefixToAddressLen(subnet string) (string, int) {
	prefix := strings.Split(subnet, "/")
	address := prefix[0]
	prefixlen, _ := strconv.Atoi(prefix[1])
	return address, prefixlen
}

func escapeFQN(input []string) []string {
	result := make([]string, 0, len(input))
	for _, piece := range input {
		result = append(result, strings.Replace(piece, "_", "\\_", -1))
	}
	return result
}

func splitEscapedString(name string) []string {
	var splitIndices []int
	last := 0
	for {
		ix := strings.Index(name[last:], "_")
		if ix < 0 {
			break
		}
		abs := last + ix
		last = abs + 1
		if name[abs-1] == '\\' {
			continue
		}
		splitIndices = append(splitIndices, abs)
	}

	var result []string
	prev := 0
	for _, value := range splitIndices {
		piece := strings.Replace(name[prev:value], "\\_", "_", -1)
		result = append(result, piece)
		prev = value + 1
	}
	piece := strings.Replace(name[prev:], "\\_", "_", -1)
	result = append(result, piece)
	return result
}
