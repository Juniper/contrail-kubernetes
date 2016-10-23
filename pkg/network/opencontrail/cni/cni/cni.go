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
	"../agent"
	"../args"
	"flag"
	"fmt"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"net"
)

const CniVersion = "0.2.0"

/*
 * Apply logging configuration. We use glog packet for logging.
 * glog supports log-dir and log-level as arguments only. Simulate argument
 * passing to glog module
 */
func applyLogging(args args.LoggingArgs) {
	flag.Parse()
	flag.Lookup("log_dir").Value.Set(args.Dir)
	flag.Lookup("v").Value.Set(args.Level)
	return
}

// Common code for both delete and add
func cmdCommon(skelArgs *skel.CmdArgs, cmd string) (*args.CniArgs, error) {
	cniArgs, err := args.Get(skelArgs)
	if err != nil {
		return nil, err
	}

	// Set logging
	applyLogging(cniArgs.ContrailArgs.Logging)
	glog.V(2).Info(fmt.Sprintf("%s with ContainerId : <%s>, Netns : <%s>, IfName : <%s>, Args <%s>, Stdin %s\n",
		cmd, skelArgs.ContainerID, skelArgs.Netns, skelArgs.IfName,
		skelArgs.Args, string(skelArgs.StdinData)))
	glog.V(2).Info(fmt.Sprintf("Parsed information %+v\n", cniArgs))

	return cniArgs, nil
}

/****************************************************************************
 * ADD message handlers
 ****************************************************************************/
// Container handling for add message
// 1. Create veth-pair interface
// 2. Set MAC address for interface inside the container
// 3. Apply IPAM configuration including,
//    - Assign IP address to the interface inside container
//    - Create the veth pairs and get host-os name for interface
func processContainerAdd(netns ns.NetNS, cniArgs *args.CniArgs, mac string,
	typesResult *types.Result) (string, error) {
	// Validate MAC address
	hwAddr, mac_err := net.ParseMAC(mac)
	if mac_err != nil {
		return "", fmt.Errorf("Error parsing MAC address ", mac, " Error ",
			mac_err)
	}

	var hostIfName string
	// Configure the container
	err := netns.Do(func(hostNS ns.NetNS) error {
		// create veth pair in container and move host end into host netns
		link, _, err := ip.SetupVeth(cniArgs.IfName, cniArgs.ContrailArgs.Mtu,
			hostNS)
		if err != nil {
			return err
		}
		hostIfName = link.Attrs().Name

		// Update MAC address for the interface
		err = ip.SetHWAddr(cniArgs.IfName, hwAddr)
		if err != nil {
			return err
		}

		// Configure IPAM attributes
		err = ipam.ConfigureIface(cniArgs.IfName, typesResult)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	return hostIfName, nil
}

// VRouter handling for add message
func processVRouterAdd(agent *agent.Connection, cniArgs *args.CniArgs,
	hostIfName string) (error, error) {
	// Send AddVm IPC to contrail-vrouter agent
	return agent.AddVm(cniArgs.K8SArgs.PodName, cniArgs.Netns,
		cniArgs.ContainerID, hostIfName, cniArgs.IfName)
}

// Get VMI parameters from VRouter
func getVmiFromVRouter(agent *agent.Connection,
	cniArgs *args.CniArgs) (*agent.Result, error) {
	result, err := agent.GetVmiInfo(cniArgs.ContainerID, cniArgs.IfName,
		cniArgs.ContrailArgs.VRouterArgs.PollTimeout,
		cniArgs.ContrailArgs.VRouterArgs.PollRetries)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ADD command handler
func CmdAdd(skelArgs *skel.CmdArgs) error {
	cniArgs, err := cmdCommon(skelArgs, "Add")
	defer glog.Flush()
	if err != nil {
		// Error parsing arguments is treated as Fatal error
		return err
	}

	// Get handle to the Namespace
	netns, err := ns.GetNS(cniArgs.Netns)
	if err != nil {
		// Error in opening namespace. Treat as fatal error
		msg := fmt.Sprintf("Failed to open netns %s: %v", cniArgs.Netns, err)
		glog.Error(msg)
		return fmt.Errorf(msg)
	}
	defer netns.Close()

	// Initialize connection to VRouter
	connection, err := agent.Init(cniArgs.K8SArgs.PodName,
		cniArgs.ContrailArgs.Dir, cniArgs.ContrailArgs.VRouterArgs.Ip,
		cniArgs.ContrailArgs.VRouterArgs.Port)
	if err != nil {
		glog.Error(fmt.Sprintf("Error initializing connection : %s",
			err.Error()))
		return err
	}
	defer connection.Close()

	// We need to get few arguments such as MAC address from VRouter. So, fetch
	// VMI parametrs from VRouter first
	result, err := getVmiFromVRouter(connection, cniArgs)
	if err != nil {
		glog.Error(fmt.Sprintf("Error querying vmi <%s> from VRouter : %s",
			cniArgs.K8SArgs.PodName, err.Error()))
		return err
	}

	// Translate result from VRouter format to Cni-Types
	typesResult := args.VRouterResultToCniResult(result)

	// Create the veth pairs and configure them
	// The container-part is added to the nets provided to CNI
	hostIfName, err := processContainerAdd(netns, cniArgs, result.Mac,
		typesResult)
	if err != nil {
		glog.Error(fmt.Sprintf("Error modifying container <%s> : %s",
			cniArgs.K8SArgs.PodName, err.Error()))
		return err
	}

	// Send add message to vrouter
	var warn error
	err, warn = processVRouterAdd(connection, cniArgs, hostIfName)
	if err != nil {
		glog.Error(fmt.Sprintf("Error adding interface to VRouter : %s",
			err.Error()))
		return err
	}

	if warn != nil {
		glog.Warning(fmt.Sprintf("Error adding interface to VRouter : %s",
			warn.Error()))
	}
	glog.V(2).Info(fmt.Sprintf("Result : %+v", typesResult))
	return typesResult.Print()
}

/****************************************************************************
 * DEL message handlers
 ****************************************************************************/
// Container DEL handler
// Deletes interface from the container
func processContainerDel(netns ns.NetNS, cniArgs *args.CniArgs) error {
	// Remove interface from the netlink
	var ipn *net.IPNet
	err := ns.WithNetNSPath(cniArgs.Netns, func(_ ns.NetNS) error {
		// Get the link
		iface, err := netlink.LinkByName(cniArgs.IfName)
		if err != nil {
			// Link already deleted. Nothing else to do
			return nil
		}

		// Delete the link from container
		ipn, err = ip.DelLinkByNameAddr(cniArgs.IfName, netlink.FAMILY_V4)
		if err != nil {
			if err = netlink.LinkDel(iface); err != nil {
				return fmt.Errorf("failed to delete %q: %v", cniArgs.IfName,
					err)
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
func processVRouterDel(agent *agent.Connection, cniArgs *args.CniArgs) error {
	// Let VRouter handle DEL command
	return agent.DelVm(cniArgs.K8SArgs.PodName)
}

// DEL command handler
// Do best effort of cleanup ignoring any intermediate errors
func CmdDel(skelArgs *skel.CmdArgs) error {
	var ret error
	cniArgs, err := cmdCommon(skelArgs, "Add")
	defer glog.Flush()
	if err != nil {
		// Error parsing arguments is treated as Fatal error
		return err
	}

	// Get handle to the Namespace
	netns, err := ns.GetNS(cniArgs.Netns)
	if err == nil {
		defer netns.Close()
		// Cleanup interfaces created
		// If namespace cannot be open, then most likely the interfaces are
		// already deleted. So no container cleanup is needed
		err = processContainerDel(netns, cniArgs)
		if err != nil {
			ret = fmt.Errorf("Error in cleanup of interfaces for DEL. Error ",
				err)
		}
	}

	connection, err := agent.Init(cniArgs.K8SArgs.PodName,
		cniArgs.ContrailArgs.Dir, cniArgs.ContrailArgs.VRouterArgs.Ip,
		cniArgs.ContrailArgs.VRouterArgs.Port)
	if err != nil {
		// Initialize connection to VRouter
		glog.Error(fmt.Sprintf("Error initializing connection : %s",
			err.Error()))
	}
	if err == nil {
		defer connection.Close()
	}

	// VRouter handling next
	err = processVRouterDel(connection, cniArgs)
	if err != nil {
		ret = fmt.Errorf("Error in VRouter cleanup for DEL. Error ", err)
	}

	if err != nil {
		glog.Error(ret.Error())
	} else {
		glog.V(2).Info(fmt.Sprintf("Del successful"))
	}

	return ret
}
