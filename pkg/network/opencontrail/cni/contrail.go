package main

import (
	"./cni"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

/****************************************************************************
 * Main
 ****************************************************************************/
func main() {
	// Let the CNI skeletal code handle basic demux based on env variables
	skel.PluginMain(cni.CmdAdd, cni.CmdDel,
		version.PluginSupports(cni.CniVersion))
}
