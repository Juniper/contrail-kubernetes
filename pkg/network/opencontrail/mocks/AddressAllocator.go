package mocks

import "github.com/stretchr/testify/mock"

type AddressAllocator struct {
	mock.Mock
}

func (m *AddressAllocator) LocateIpAddress(uid string) (string, error) {
	ret := m.Called(uid)

	r0 := ret.Get(0).(string)
	r1 := ret.Error(1)

	return r0, r1
}
func (m *AddressAllocator) ReleaseIpAddress(uid string) {
	m.Called(uid)
}
