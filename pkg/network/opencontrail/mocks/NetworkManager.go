package mocks

import "github.com/stretchr/testify/mock"

import "github.com/Juniper/contrail-go-api/types"

type NetworkManager struct {
	mock.Mock
}

func (m *NetworkManager) LocateFloatingIpPool(network *types.VirtualNetwork, name string, subnet string) *types.FloatingIpPool {
	ret := m.Called(network, name, subnet)

	var r0 *types.FloatingIpPool
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.FloatingIpPool)
	}

	return r0
}
func (m *NetworkManager) DeleteFloatingIpPool(network *types.VirtualNetwork, name string, cascade bool) error {
	ret := m.Called(network, name, cascade)

	r0 := ret.Error(0)

	return r0
}
func (m *NetworkManager) LookupNetwork(projectName string, networkName string) *types.VirtualNetwork {
	ret := m.Called(projectName, networkName)

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}

	return r0
}
func (m *NetworkManager) LocateNetwork(project string, name string, subnet string) *types.VirtualNetwork {
	ret := m.Called(project, name, subnet)

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}

	return r0
}
func (m *NetworkManager) DeleteNetwork(_a0 *types.VirtualNetwork) error {
	ret := m.Called(_a0)

	r0 := ret.Error(0)

	return r0
}
func (m *NetworkManager) ReleaseNetworkIfEmpty(namespace string, name string) {
	m.Called(namespace, name)
}
func (m *NetworkManager) LocateFloatingIp(networkName string, resourceName string, address string) *types.FloatingIp {
	ret := m.Called(networkName, resourceName, address)

	var r0 *types.FloatingIp
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.FloatingIp)
	}

	return r0
}
func (m *NetworkManager) GetGatewayAddress(network *types.VirtualNetwork) (string, error) {
	ret := m.Called(network)

	r0 := ret.Get(0).(string)
	r1 := ret.Error(1)

	return r0, r1
}
