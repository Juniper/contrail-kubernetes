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

type ServiceId struct {
	Namespace string
	Service   string
}

type ServiceIdList []ServiceId

func (s *ServiceIdList) Contains(namespace, service string) bool {
	for _, entry := range *s {
		if entry.Namespace == namespace && entry.Service == service {
			return true
		}
	}
	return false
}
func (s *ServiceIdList) Add(namespace, service string) {
	if s.Contains(namespace, service) {
		return
	}
	*s = append(*s, ServiceId{namespace, service})
}

func MakeServiceIdList() ServiceIdList {
	return make(ServiceIdList, 0)
}

// serviceIdFromName splits a prevalidated string in the form namespace/service-name.
func serviceIdFromName(name string) (string, string) {
	tuple := strings.Split(name, "/")
	return tuple[0], tuple[1]
}

func AppendConst(slice []string, element string) []string {
	newSlice := make([]string, len(slice), len(slice)+1)
	copy(newSlice, slice)
	return append(newSlice, element)
}

func PrefixToAddressLen(subnet string) (string, int) {
	prefix := strings.Split(subnet, "/")
	address := prefix[0]
	prefixlen, _ := strconv.Atoi(prefix[1])
	return address, prefixlen
}
