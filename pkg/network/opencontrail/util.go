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
