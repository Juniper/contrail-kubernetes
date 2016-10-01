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

/* Common code to parse agruments for both Kubernetes and Mesos. */
package args

import (
	"../ipc"
	"encoding/json"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"log"
	"net"
	"strings"
)

/****************************************************************************
 * Argument handling
 ****************************************************************************/
const modek8s = "kubernetes"
const modeMesos = "mesos"
const k8sDir = "/var/contrail/k8s"
const mesosDir = "/var/contrail/mesos"
const pollTimeout = "100ms"
const pollRetries = 10
const vrouterIp = "127.0.0.1"
const vrouterPort = 9091

/* Example configuration for Contrail
    {
        "cniVersion": "0.2.0",
        "contrail" : {
            "vrouter" : {
                "ip" : "127.0.0.1",
                "port" : 9091,
				"timeout" : "2000ms"
				"retries" : 10
            },
            "mode" : "k8s"
            "mtu" : 1500
			"dir" : "/var/contrail/vm"
        },

        "name": "contrail",
        "type": "contrail"
    }
*/

// Definitions to get VRouter related parameters from json data
type VRouterArgs struct {
	Ip          string `json:"ip"`
	Port        int    `json:"port"`
	PollTimeout string `json:"pollTimeout"`
	PollRetries int    `json:"pollRetries"`
}

// Contrail specific arguments
type ContrailArgs struct {
	VRouterArgs VRouterArgs `json:"vrouter"`
	Mode        string      `json:"mode"`
	Mtu         int         `json:"mtu"`
	Dir         string      `json:"dir"`
}

// Kubernetes specific arguments
type K8SArgs struct {
	NameSpace string
	PodName   string
}

// Definition of json data in STDIN
type CniArgs struct {
	ContrailArgs ContrailArgs `json:"contrail"`
	ContainerID  string
	IfName       string
	Netns        string
	K8SArgs      K8SArgs
}

/*
 * Get Kubernetes specific arguments
 * Format of arguments in case of kubernetes is
 * "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=hello-world-1-81nl8;
 *  K8S_POD_INFRA_CONTAINER_ID=<container-id>"
 */
func (k8sArgs *K8SArgs) getK8sArgs(args *skel.CmdArgs) {
	cniArgs := strings.Split(args.Args, ";")
	for _, v := range cniArgs {
		a := strings.Split(v, "=")
		if len(a) >= 2 {
			if a[0] == "K8S_POD_NAMESPACE" {
				k8sArgs.NameSpace = a[1]
			}
			if a[0] == "K8S_POD_NAME" {
				k8sArgs.PodName = a[1]
			}
		}
	}
}

// Fetch all parameters. Includes parameters from STDIN and Environemnt vars
func Get(args *skel.CmdArgs) (*CniArgs, error) {
	// Set defaults
	vrouterArgs := VRouterArgs{Ip: vrouterIp, Port: vrouterPort,
		PollTimeout: pollTimeout, PollRetries: pollRetries}
	contrailArgs := ContrailArgs{VRouterArgs: vrouterArgs, Dir: k8sDir}
	cniArgs := &CniArgs{ContrailArgs: contrailArgs}

	// Parse json data
	if err := json.Unmarshal(args.StdinData, cniArgs); err != nil {
		log.Printf("Invalid JSon string <%s>\n", args.StdinData)
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	cniArgs.ContainerID = args.ContainerID
	cniArgs.Netns = args.Netns
	cniArgs.IfName = args.IfName
	// Get Kubernetes parameters
	cniArgs.K8SArgs.getK8sArgs(args)
	return cniArgs, nil
}

// Convert cniArgs from VRouter format to CNI format
func VRouterResultToCniResult(ipc *ipc.Result) *types.Result {
	mask := net.CIDRMask(ipc.Plen, 32)
	ipv4 := types.IPConfig{IP: net.IPNet{IP: net.ParseIP(ipc.Ip),
		Mask: mask}, Gateway: net.ParseIP(ipc.Gw)}
	result := &types.Result{IP4: &ipv4}

	_, defaultNet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return nil
	}
	result.IP4.Routes = append(result.IP4.Routes,
		types.Route{Dst: *defaultNet, GW: result.IP4.Gateway})

	result.DNS.Nameservers = append(result.DNS.Nameservers, ipc.Dns)
	return result
}
