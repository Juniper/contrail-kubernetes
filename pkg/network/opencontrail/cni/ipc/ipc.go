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
package ipc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"time"
)

func makeFileName(dir, vm string) string {
	return dir + "/" + vm
}

/****************************************************************************
 * Connection handling
 ****************************************************************************/
/* struct to hold data for a connection to VRouter */
type Connection struct {
	url    string
	dir    string // config files are stored here for persistency
	client *rpc.Client
}

func (conn *Connection) doOp(op string, msg []byte) (*http.Response, error) {
	req, err := http.NewRequest(op, conn.url, bytes.NewBuffer(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		log.Println("JSON op fail")
		return nil, err
	}

	log.Println("JSON op successful")
	return resp, nil
}

/****************************************************************************
 * ADD message handling
 ****************************************************************************/
// RPC Message definition
type contrailAddRpc struct {
	Time            string `json:"time"`
	Vm              string `json:"vm"`
	Mac             string `json:"mac"`
	HostIfName      string `json:"hostIfName"`
	ContainerIfName string `json:"containerIfName"`
	PodName         string `json:"podName"`
	Namespace       string `json:"nameSpace"`
}

// Make JSON for RPC
func makeAddRpc(podName, nameSpace, containerId, hostIfName,
	containerIfName string) *contrailAddRpc {
	t := time.Now()
	rpc := contrailAddRpc{Time: t.String(), Vm: containerId,
		HostIfName: hostIfName, ContainerIfName: containerIfName,
		PodName: podName, Namespace: nameSpace}
	return &rpc
}

// Store the config to file for persistency
func (conn *Connection) addVmToFile(rpc *contrailAddRpc) error {
	_, err := os.Stat(conn.dir)
	if err != nil {
		log.Println("Error reading VM config directory ", conn.dir,
			" Error : ", err)
		return err
	}

	// Write file based on VM name
	fname := makeFileName(conn.dir, rpc.Vm)
	rpcJson, _ := json.MarshalIndent(rpc, "", "\t")
	err = ioutil.WriteFile(fname, rpcJson, 0644)
	if err != nil {
		log.Println("Error writing VM config file ", fname, " Error : ", err)
		return err
	}

	return nil
}

func (conn *Connection) addVmToRpc(rpc *contrailAddRpc) error {
	msg, err := json.MarshalIndent(rpc, "", "\t")
	if err != nil {
		return err
	}

	resp, err := conn.doOp("POST", msg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Error in ADD VM message to VRouter. Code : ",
			resp.StatusCode)
		return fmt.Errorf("Error in ADD VM message to VRouter. Code : ",
			resp.StatusCode)
	}

	return nil
}

/* Process add of a VM. Writes config file and send RPC to agent */
func (conn *Connection) AddVm(podName, nameSpace, containerId, hostIfName,
	containerIfName string) error {
	// Make RPC structure
	rpc := makeAddRpc(podName, nameSpace, containerId, hostIfName,
		containerIfName)

	// Store config to file for persistency
	if err := conn.addVmToFile(rpc); err != nil {
		// Fail adding VM if directory not present
		return err
	}

	// Make the RPC call
	if err := conn.addVmToRpc(rpc); err != nil {
		/* Dont fail if RPC command fails. Maybe agent is down and will
		 * comeback shortly. When VRouter comes back, PollVM will have chance
		 * to succeed
		 */
		return nil
	}

	return nil
}

/****************************************************************************
 * DEL message handling
 ****************************************************************************/
// RPC Message definition
type contrailDelRpc struct {
	vm string `json:"vm"`
}

// Make RPC call
func makeDelRpc(containerId string) *contrailDelRpc {
	rpc := contrailDelRpc{vm: containerId}
	return &rpc
}

// Del VM config file
func (conn *Connection) delVmToFile(rpc *contrailDelRpc) error {
	fname := makeFileName(conn.dir, rpc.vm)
	_, err := os.Stat(fname)
	// File not present... noting to do
	if err != nil {
		log.Println("VM config file ", fname, " not present.",
			" Skipping config file delete")
		return nil
	}

	// Delete file
	err = os.Remove(fname)
	if err != nil {
		log.Println("Error deleteing VM config file ", fname, " Error : ", err)
		return err
	}

	return nil
}

func (conn *Connection) delVmToRpc(rpc *contrailDelRpc) error {
	msg, err := json.MarshalIndent(rpc, "", "\t")
	if err != nil {
		return err
	}

	resp, err := conn.doOp("DELETE", msg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("Error in DEL VM message to VRouter. Code : ",
			resp.StatusCode)
		return fmt.Errorf("Error in DEL VM message to VRouter. Code : ",
			resp.StatusCode)
	}
	return nil
}

func (conn *Connection) DelVm(containerId string) error {
	// Make RPC structure
	rpc := makeDelRpc(containerId)

	// Remove the configuraion file stored for persistency
	if err := conn.delVmToFile(rpc); err != nil {
		return err
	}

	// Make the RPC call
	if err := conn.delVmToRpc(rpc); err != nil {
		return nil
	}

	return nil
}

/****************************************************************************
 * POLL message handling
 ****************************************************************************/
type Result struct {
	Vm   string `json:"vm"`
	Ip   string `json:"ip"`
	Plen int    `json:"plen"`
	Gw   string `json:"gw"`
	Dns  string `json:"dns"`
	Mac  string `json:"mac"`
}

type contrailVmRpcReq struct {
	vm string `json:"vm"`
}

func initPollVmReq(instanceId string) *contrailVmRpcReq {
	return &contrailVmRpcReq{vm: instanceId}
}

func (conn *Connection) pollVmOnce(instanceId string) (*Result, error) {
	rpc := initPollVmReq(instanceId)
	msg, err := json.MarshalIndent(rpc, "", "\t")
	if err != nil {
		return nil, err
	}

	resp, err := conn.doOp("GET", msg)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error polling VM. Status ", resp.StatusCode)
	}

	var result Result
	var body []byte

	body, err = ioutil.ReadAll(resp.Body)
	log.Println("Read data ", string(body), err)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (conn *Connection) GetVmiInfo(instanceId, ifName string,
	delay string, count int) (*Result, error) {
	for i := 0; i < count; i++ {
		log.Println("Polling ", i)
		result, err := conn.pollVmOnce(instanceId)
		if err == nil {
			return result, nil
		}

		log.Println("Error in Get ", err)
		var d time.Duration
		d, err = time.ParseDuration(delay)
		if err != nil {
			d, err = time.ParseDuration(delay)
		}

		time.Sleep(d)
	}

	return nil, fmt.Errorf("Failed in PollVM for instance %s", instanceId)
}

/****************************************************************************
 * Connection handlers
 ****************************************************************************/
func (conn *Connection) Close() error {
	return nil
}

func Init(vm, dir, server string, port int) (*Connection, error) {
	// Verify directory
	if dir == "" {
		return nil, fmt.Errorf("Directory name not specified")
	}

	// Init connection structure
	url := "http://" + server + ":" + strconv.Itoa(port) + "/container/" + vm
	conn := Connection{url: url, dir: dir, client: nil}
	return &conn, nil
}
