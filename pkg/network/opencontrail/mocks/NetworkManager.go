package mocks

import (
	"github.com/stretchr/testify/mock"

	"github.com/Juniper/contrail-go-api/types"
)

// NetworkManager provides a Mock of the NetworkManager interface
type NetworkManager struct {
	mock.Mock
}

// LocateFloatingIPPool mock implementation
func (m *NetworkManager) LocateFloatingIPPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error) {
	ret := m.Called(network)

	var r0 *types.FloatingIpPool
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.FloatingIpPool)
	}
	r1 := ret.Error(1)

	return r0, r1
}

// LookupFloatingIPPool mock implementation
func (m *NetworkManager) LookupFloatingIPPool(network *types.VirtualNetwork) (*types.FloatingIpPool, error) {
	ret := m.Called(network)

	var r0 *types.FloatingIpPool
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.FloatingIpPool)
	}
	r1 := ret.Error(1)

	return r0, r1
}

// DeleteFloatingIPPool mock implementation
func (m *NetworkManager) DeleteFloatingIPPool(network *types.VirtualNetwork, cascade bool) error {
	ret := m.Called(network, cascade)

	r0 := ret.Error(0)

	return r0
}

// LookupNetwork mock implementation
func (m *NetworkManager) LookupNetwork(projectName string, networkName string) (*types.VirtualNetwork, error) {
	ret := m.Called(projectName, networkName)

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}
	r1 := ret.Error(1)

	return r0, r1
}

// LocateNetwork mock implementation
func (m *NetworkManager) LocateNetwork(project string, name string, subnet string) (*types.VirtualNetwork, error) {
	ret := m.Called(project, name, subnet)

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}
	r1 := ret.Error(1)

	return r0, r1
}

// DeleteNetwork mock implementation
func (m *NetworkManager) DeleteNetwork(_a0 *types.VirtualNetwork) error {
	ret := m.Called(_a0)

	r0 := ret.Error(0)

	return r0
}

// ReleaseNetworkIfEmpty mock implementation
func (m *NetworkManager) ReleaseNetworkIfEmpty(namespace string, name string) (bool, error) {
	ret := m.Called(namespace, name)

	r0 := ret.Get(0).(bool)
	r1 := ret.Error(1)

	return r0, r1
}

// LocateFloatingIP mock implementation
func (m *NetworkManager) LocateFloatingIP(network *types.VirtualNetwork, resourceName string, address string) (*types.FloatingIp, error) {
	ret := m.Called(network, resourceName, address)

	var r0 *types.FloatingIp
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.FloatingIp)
	}
	r1 := ret.Error(1)

	return r0, r1
}

// DeleteFloatingIP mock implementation
func (m *NetworkManager) DeleteFloatingIP(network *types.VirtualNetwork, resourceName string) error {
	ret := m.Called(network, resourceName)

	r0 := ret.Error(0)

	return r0
}

// GetPublicNetwork mock implementation
func (m *NetworkManager) GetPublicNetwork() *types.VirtualNetwork {
	ret := m.Called()

	var r0 *types.VirtualNetwork
	if ret.Get(0) != nil {
		r0 = ret.Get(0).(*types.VirtualNetwork)
	}

	return r0
}

// GetGatewayAddress mock implementation
func (m *NetworkManager) GetGatewayAddress(network *types.VirtualNetwork) (string, error) {
	ret := m.Called(network)

	r0 := ret.Get(0).(string)
	r1 := ret.Error(1)

	return r0, r1
}

// Connect mock implementation
func (m *NetworkManager) Connect(network *types.VirtualNetwork, networkFQN string) error {
	ret := m.Called(network, networkFQN)
	r0 := ret.Error(0)
	return r0
}

// Disconnect mock implementation
func (m *NetworkManager) Disconnect(networkFQN []string, targetCDN string) error {
	ret := m.Called(networkFQN, targetCDN)
	r0 := ret.Error(0)
	return r0
}

// DeleteConnections mock implementation
func (m *NetworkManager) DeleteConnections(network *types.VirtualNetwork, policies map[string]string) error {
	ret := m.Called(network, policies)
	r0 := ret.Error(0)
	return r0
}
