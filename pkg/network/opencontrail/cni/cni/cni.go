/*
Copyright 2016 Juniper Networks, Inc. All rights reserved.

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

/* Common CNI plugin for Kubernetes and Mesos. */
package cni

import (
	"../args"
	"../ipc"
	"fmt"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
	"log"
	"net"
)

const CniVersion = "0.2.0"

/****************************************************************************
 * ADD message handlers
 ****************************************************************************/
// Create the veth pairs and get host-os name for interface
func processContainerAdd(netns ns.NetNS, cniArgs *args.CniArgs, mac string,
	typesResult *types.Result) (string, error) {
	var hostIfName string
	err := netns.Do(func(hostNS ns.NetNS) error {
		// create veth pair in container and move host end into host netns
		link, _, err := ip.SetupVeth(cniArgs.IfName, cniArgs.ContrailArgs.Mtu,
			hostNS)
		if err != nil {
			return err
		}

		hostIfName = link.Attrs().Name

		err = ipam.ConfigureIface(cniArgs.IfName, typesResult)
		if err != nil {
			return err
		}

		hwAddr, mac_err := net.ParseMAC(mac)
		if mac_err != nil {
			log.Println("Error parsing MAC address ", mac, " Error ", mac_err)
			return mac_err
		}

		err = ip.SetHWAddr(cniArgs.IfName, hwAddr)
		/*
			// Set IPv4 Address
			err = ip.SetHWAddrByIP(cniArgs.IfName, typesResult.IP4.IP.IP, nil)
			if err != nil {
				return err
			}

			eth_link, eth_err := netlink.LinkByName(cniArgs.IfName)
			if eth_err != nil {
				log.Println("Error finding interface ", cniArgs.IfName, " Error ",
					eth_err)
				return eth_err
			}

			eth_err = netlink.LinkSetHardwareAddr(eth_link, net.HardwareAddr(mac))
			log.Println("Setting hwaddr to ", net.HardwareAddr(mac))
			if eth_err != nil {
				log.Println("Setting hwaddr failed ", eth_err)
				return eth_err
			}
		*/
		return err
	})

	if err != nil {
		return "", err
	}

	return hostIfName, nil
}

func addToVRouter(ipc *ipc.Connection, cniArgs *args.CniArgs,
	hostIfName string) error {
	// Send AddVm IPC to contrail-vrouter agent
	return ipc.AddVm(cniArgs.K8SArgs.PodName, cniArgs.Netns,
		cniArgs.ContainerID, hostIfName, cniArgs.IfName)
}

// Get VMI parameters from VRouter
func getVmiFromVRouter(ipc *ipc.Connection, cniArgs *args.CniArgs) (*ipc.Result,
	error) {
	ipcResult, err := ipc.GetVmiInfo(cniArgs.ContainerID, cniArgs.IfName,
		cniArgs.ContrailArgs.VRouterArgs.PollTimeout,
		cniArgs.ContrailArgs.VRouterArgs.PollRetries)
	if err != nil {
		return nil, err
	}

	return ipcResult, nil
}

// ADD command handler
func CmdAdd(skelArgs *skel.CmdArgs) error {
	log.Println("Processing CNI Command ADD")

	cniArgs, err := args.Get(skelArgs)
	if err != nil {
		// Error parsing arguments. Treat as fatal error
		return err
	}

	// Get handle to the Namespace
	netns, err := ns.GetNS(cniArgs.Netns)
	if err != nil {
		// Error in opening namespace. Treat as fatal error
		return fmt.Errorf("failed to open netns %s: %v", cniArgs.Netns, err)
	}
	defer netns.Close()

	connection, err := ipc.Init(cniArgs.K8SArgs.PodName,
		cniArgs.ContrailArgs.Dir, cniArgs.ContrailArgs.VRouterArgs.Ip,
		cniArgs.ContrailArgs.VRouterArgs.Port)
	if err != nil {
		return err
	}

	// We need to get few arguments such as MAC address from VRouter. So, fetch
	// VMI parametrs from VRouter first
	ipcResult, err := getVmiFromVRouter(connection, cniArgs)
	if err != nil {
		return err
	}

	// Result translate from VRouter to Cni-Types
	typesResult := args.VRouterResultToCniResult(ipcResult)

	// Create the veth pairs and configure them
	// The container-part is added to the nets provided to CNI
	hostIfName, err := processContainerAdd(netns, cniArgs, ipcResult.Mac,
		typesResult)
	if err != nil {
		return err
	}

	connection, err = ipc.Init("",
		cniArgs.ContrailArgs.Dir, cniArgs.ContrailArgs.VRouterArgs.Ip,
		cniArgs.ContrailArgs.VRouterArgs.Port)
	if err != nil {
		return err
	}

	// Send add message to vrouter
	// Ignore any errors from VRouter
	err = addToVRouter(connection, cniArgs, hostIfName)
	if err != nil {
		log.Println("Error adding interface to VRouter: ", err)
	}

	return typesResult.Print()
}

/****************************************************************************
 * DEL message handlers
 ****************************************************************************/
// Container DEL handler
func processContainerDel(netns ns.NetNS, cniArgs *args.CniArgs) error {
	// Remove interface from the netlink
	var ipn *net.IPNet
	err := ns.WithNetNSPath(cniArgs.Netns, func(_ ns.NetNS) error {
		iface, err := netlink.LinkByName(cniArgs.IfName)
		// Link already deleted. Nothing else to do
		if err != nil {
			return nil
		}

		ipn, err = ip.DelLinkByNameAddr(cniArgs.IfName, netlink.FAMILY_V4)
		if err != nil {
			if err = netlink.LinkDel(iface); err != nil {
				return fmt.Errorf("failed to delete %q: %v", cniArgs.IfName, err)
			}
		}

		return err
	})
	if err != nil {
		return err
	}

	return nil
}

// VRouter DEL handler
func processVRouterDel(ipc *ipc.Connection, cniArgs *args.CniArgs) error {
	// Let VRouter handle DEL command
	return ipc.DelVm(cniArgs.K8SArgs.PodName)
}

// DEL command handler
func CmdDel(skelArgs *skel.CmdArgs) error {
	log.Println("Processing CNI Command DEL")
	var ret error

	cniArgs, err := args.Get(skelArgs)
	if err != nil {
		// Error parsing arguments. We still continue processing and cleanup
		// whatever possible
		ret = fmt.Errorf("Error parsing parameters in DEL. Error : ", err)
	}

	// Get handle to the Namespace
	netns, err := ns.GetNS(cniArgs.Netns)
	if err == nil {
		// Cleanup interfaces created
		// If namespace cannot be open, then most likely the interfaces are
		// already deleted. So no container cleanup is needed
		err = processContainerDel(netns, cniArgs)
		if err != nil {
			ret = fmt.Errorf("Error in cleanup of interfaces for DEL. Error ",
				err)
		}
	}
	defer netns.Close()

	connection, err := ipc.Init(cniArgs.K8SArgs.PodName,
		cniArgs.ContrailArgs.Dir, cniArgs.ContrailArgs.VRouterArgs.Ip,
		cniArgs.ContrailArgs.VRouterArgs.Port)
	if err != nil {
		// Error in opening namespace. Treat as fatal error
		ret = fmt.Errorf("Failing creating VRouter connection for DEL. Error ",
			err)
	}

	// VRouter handling next
	err = processVRouterDel(connection, cniArgs)
	if err != nil {
		ret = fmt.Errorf("Error in VRouter cleanup for DEL. Error ", err)
	}

	return ret
}
