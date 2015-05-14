package mocks

import "github.com/stretchr/testify/mock"

import "github.com/Juniper/contrail-go-api/types"

type NetworkManager struct {
	mock.Mock
}

func (m *NetworkManager) LocateFloatingIpPool(network *types.VirtualNetwork, subnet string) (*types.FloatingIpPool, error) {
	ret := m.Called(network, subnet)

	var r0 *types.FloatingIpPool
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.FloatingIpPool)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *NetworkManager) DeleteFloatingIpPool(network *types.VirtualNetwork, cascade bool) error {
	ret := m.Called(network, cascade)

	r0 := ret.Error(0)

	return r0
}
func (m *NetworkManager) LookupNetwork(projectName string, networkName string) (*types.VirtualNetwork, error) {
	ret := m.Called(projectName, networkName)

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *NetworkManager) LocateNetwork(project string, name string, subnet string) (*types.VirtualNetwork, error) {
	ret := m.Called(project, name, subnet)

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *NetworkManager) DeleteNetwork(_a0 *types.VirtualNetwork) error {
	ret := m.Called(_a0)

	r0 := ret.Error(0)

	return r0
}
func (m *NetworkManager) ReleaseNetworkIfEmpty(namespace string, name string) error {
	ret := m.Called(namespace, name)

	r0 := ret.Error(0)

	return r0
}
func (m *NetworkManager) LocateFloatingIp(network *types.VirtualNetwork, resourceName string, address string) (*types.FloatingIp, error) {
	ret := m.Called(network, resourceName, address)

	var r0 *types.FloatingIp
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.FloatingIp)
	}
	r1 := ret.Error(1)

	return r0, r1
}
func (m *NetworkManager) GetPublicNetwork() *types.VirtualNetwork {
	ret := m.Called()

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}

	return r0
}
func (m *NetworkManager) GetGatewayAddress(network *types.VirtualNetwork) (string, error) {
	ret := m.Called(network)

	r0 := ret.Get(0).(string)
	r1 := ret.Error(1)

	return r0, r1
}
