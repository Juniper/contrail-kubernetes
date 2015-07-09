package mocks

import "github.com/stretchr/testify/mock"

type Store struct {
	mock.Mock
}

func (m *Store) Add(obj interface{}) error {
	ret := m.Called(obj)

	r0 := ret.Error(0)

	return r0
}
func (m *Store) Update(obj interface{}) error {
	ret := m.Called(obj)

	r0 := ret.Error(0)

	return r0
}
func (m *Store) Delete(obj interface{}) error {
	ret := m.Called(obj)

	r0 := ret.Error(0)

	return r0
}
func (m *Store) List() []interface{} {
	ret := m.Called()

	var r0 []interface{}
	if ret.Get(0) != nil {
		r0 = ret.Get(0).([]interface{})
	}

	return r0
}
func (m *Store) ListKeys() []string {
	ret := m.Called()

	var r0 []string
	if ret.Get(0) != nil {
		r0 = ret.Get(0).([]string)
	}

	return r0
}
func (m *Store) Get(obj interface{}) (interface{}, bool, error) {
	ret := m.Called(obj)

	var r0 interface{}
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(interface{})
	}
	r1 := ret.Get(1).(bool)
	r2 := ret.Error(2)

	return r0, r1, r2
}
func (m *Store) GetByKey(key string) (interface{}, bool, error) {
	ret := m.Called(key)

	var r0 interface{}
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(interface{})
	}
	r1 := ret.Get(1).(bool)
	r2 := ret.Error(2)

	return r0, r1, r2
}
func (m *Store) Replace(_a0 []interface{}) error {
	ret := m.Called(_a0)

	r0 := ret.Error(0)

	return r0
}
