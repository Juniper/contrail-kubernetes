package mocks

import "github.com/stretchr/testify/mock"

import "github.com/GoogleCloudPlatform/kubernetes/pkg/api"
import "github.com/GoogleCloudPlatform/kubernetes/pkg/fields"
import "github.com/GoogleCloudPlatform/kubernetes/pkg/labels"
import "github.com/GoogleCloudPlatform/kubernetes/pkg/watch"

type KubePodInterface struct {
	mock.Mock
}

func (m *KubePodInterface) List(label labels.Selector, field fields.Selector) (*api.PodList, error) {
	ret := m.Called(label, field)

	var r0 *api.PodList
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.PodList)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubePodInterface) Get(name string) (*api.Pod, error) {
	ret := m.Called(name)

	var r0 *api.Pod
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Pod)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubePodInterface) Delete(name string, options *api.DeleteOptions) error {
	ret := m.Called(name, options)

	r0 := ret.Error(0)

	return r0
}
func (m *KubePodInterface) Create(pod *api.Pod) (*api.Pod, error) {
	ret := m.Called(pod)

	var r0 *api.Pod
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Pod)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubePodInterface) Update(pod *api.Pod) (*api.Pod, error) {
	ret := m.Called(pod)

	var r0 *api.Pod
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Pod)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubePodInterface) Watch(label labels.Selector, field fields.Selector, resourceVersion string) (watch.Interface, error) {
	ret := m.Called(label, field, resourceVersion)

	r0 := ret.Get(0).(watch.Interface)
	r1 := ret.Error(1)

	return r0, r1
}
func (m *KubePodInterface) Bind(binding *api.Binding) error {
	ret := m.Called(binding)

	r0 := ret.Error(0)

	return r0
}
func (m *KubePodInterface) UpdateStatus(pod *api.Pod) (*api.Pod, error) {
	ret := m.Called(pod)

	var r0 *api.Pod
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*api.Pod)
	}
	r1 := ret.Error(1)

	return r0, r1
}
