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
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"k8s.io/kubernetes/pkg/api"
)

func TestServiceIdList(t *testing.T) {
	config := NewConfig()
	config.NamespaceServices = nil
	pod := &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Name:      "test-xz1",
			Namespace: "testns",
			Labels: map[string]string{
				config.NetworkTag:       "testpod",
				config.NetworkAccessTag: "service1",
			},
		},
	}

	list := MakeServiceIdList()

	// ServiceIdList is a slice; it must be passed as a pointer in order to be
	// modified.
	buildPodServiceList(pod, config, &list)

	if len(list) != 1 {
		t.Errorf("expected list length 1, got %d", len(list))
	}
	names := make([]string, 0)
	for _, v := range list {
		names = append(names, v.Service)
	}
	if !reflect.DeepEqual(names, []string{"service1"}) {
		t.Errorf("expected [\"service1\"], got %+v", names)
	}
}

func TestEscapedNames(t *testing.T) {
	values := []string{
		"a_b:c_d:x",
		"a\\_b:c_d:x",
		"foo:bar:baz",
	}
	for _, v := range values {
		escapedName := escapeFQN(strings.Split(v, ":"))
		result := splitEscapedString(strings.Join(escapedName, ":"))
		assert.Equal(t, v, strings.Join(result, ":"))
	}
}
