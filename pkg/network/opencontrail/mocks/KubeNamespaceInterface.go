package mocks

import (
	"github.com/stretchr/testify/mock"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/watch"
)

type KubeNamespaceInterface struct {
	mock.Mock
}

func (m *KubeNamespaceInterface) Create(item *api.Namespace) (*api.Namespace, error) {
	ret := m.Called(item)

	var r0 *api.Namespace
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Namespace)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubeNamespaceInterface) Get(name string) (*api.Namespace, error) {
	ret := m.Called(name)

	var r0 *api.Namespace
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Namespace)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubeNamespaceInterface) List(opts unversioned.ListOptions) (*api.NamespaceList, error) {
	ret := m.Called(opts)

	var r0 *api.NamespaceList
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.NamespaceList)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubeNamespaceInterface) Delete(name string) error {
	ret := m.Called(name)

	r0 := ret.Error(0)

	return r0
}
func (m *KubeNamespaceInterface) Update(item *api.Namespace) (*api.Namespace, error) {
	ret := m.Called(item)

	var r0 *api.Namespace
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Namespace)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubeNamespaceInterface) Watch(opts unversioned.ListOptions) (watch.Interface, error) {
	ret := m.Called(opts)

	r0 := ret.Get(0).(watch.Interface)
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubeNamespaceInterface) Finalize(item *api.Namespace) (*api.Namespace, error) {
	ret := m.Called(item)

	var r0 *api.Namespace
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Namespace)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubeNamespaceInterface) Status(item *api.Namespace) (*api.Namespace, error) {
	ret := m.Called(item)

	var r0 *api.Namespace
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Namespace)
	}
	r1 := ret.Error(1)

	return r0, r1
}
