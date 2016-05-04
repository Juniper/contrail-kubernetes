package mocks

import "github.com/stretchr/testify/mock"

// AddressAllocator provides a mock implementation of the AddressAllocator interface
type AddressAllocator struct {
	mock.Mock
}

// LocateIPAddress allocates an IP address
func (m *AddressAllocator) LocateIPAddress(uid string) (string, error) {
	ret := m.Called(uid)

	r0 := ret.Get(0).(string)
	r1 := ret.Error(1)

	return r0, r1
}

// ReleaseIPAddress frees an allocated address
func (m *AddressAllocator) ReleaseIPAddress(uid string) {
	m.Called(uid)
}
