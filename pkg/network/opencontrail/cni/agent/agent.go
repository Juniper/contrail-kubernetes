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
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"
)

/****************************************************************************
 * Connection handling
 ****************************************************************************/
/* struct to hold data for a connection to VRouter Agent */
type Connection struct {
	server     string
	port       int
	vm         string
	dir        string // config files are stored here for persistency
	httpClient *http.Client
}

// Make filename to store config
func (conn *Connection) makeFileName() string {
	return conn.dir + "/label-" + conn.vm
}

// Make URL for operation
func (conn *Connection) makeUrl(addVm bool) string {
	url := "http://" + conn.server + ":" + strconv.Itoa(conn.port) + "/port"
	if addVm {
		url = url + "/" + conn.vm
	}
	return url
}

func (conn *Connection) doOp(op string, addVm bool,
	msg []byte) (*http.Response, error) {
	url := conn.makeUrl(addVm)
	req, err := http.NewRequest(op, url, bytes.NewBuffer(msg))
	if err != nil {
		return nil, fmt.Errorf("Error creating http Request <%s>",
			err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := conn.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP operation failed <%s>", err)
	}

	return resp, nil
}

/****************************************************************************
 * ADD message handling
 ****************************************************************************/
// Add Message definition
type contrailAddMsg struct {
	Time            string `json:"time"`
	Vm              string `json:"vm-label"`
	VmId            string `json:"vm-id"`
	Nw              string `json:"network-label"`
	HostIfName      string `json:"ifname"`
	ContainerIfName string `json:"vm-ifname"`
	Namespace       string `json:"namespace"`
}

// Make JSON for Add Message
func makeAddMsg(podName, nameSpace, containerId, hostIfName,
	containerIfName string) *contrailAddMsg {
	t := time.Now()
	addMsg := contrailAddMsg{Time: t.String(), Vm: podName, VmId: containerId,
		HostIfName: hostIfName, ContainerIfName: containerIfName,
		Namespace: nameSpace}
	return &addMsg
}

// Store the config to file for persistency
func (conn *Connection) addVmToFile(addMsg *contrailAddMsg) error {
	_, err := os.Stat(conn.dir)
	if err != nil {
		return fmt.Errorf("Error reading VM config directory %s. Error %s",
			conn.dir, err)
	}

	// Write file based on VM name
	fname := conn.makeFileName()
	rpcJson, _ := json.MarshalIndent(addMsg, "", "\t")
	err = ioutil.WriteFile(fname, rpcJson, 0644)
	if err != nil {
		return fmt.Errorf("Error writing VM config file %s. Error %s",
			fname, err)
	}

	return nil
}

func (conn *Connection) addVmToAgent(addMsg *contrailAddMsg) error {
	msg, err := json.MarshalIndent(addMsg, "", "\t")
	if err != nil {
		return err
	}

	resp, err := conn.doOp("POST", false, msg)
	if err != nil {
		return fmt.Errorf("Error in POST operation. %s", err)
	}
	defer resp.Body.Close()

	if (resp.StatusCode != http.StatusOK) &&
		(resp.StatusCode != http.StatusCreated) {
		return fmt.Errorf("Agent returned error for VM ADD message. Code : ",
			resp.StatusCode)
	}

	return nil
}

/* Process add of a VM. Writes config file and send message to agent */
func (conn *Connection) AddVm(podName, nameSpace, containerId, hostIfName,
	containerIfName string) (error, error) {
	// Make Add Message structure
	addMsg := makeAddMsg(podName, nameSpace, containerId, hostIfName,
		containerIfName)

	// Store config to file for persistency
	if err := conn.addVmToFile(addMsg); err != nil {
		// Fail adding VM if directory not present
		return fmt.Errorf("Agent error creating config file : %s", err), nil
	}

	// Make the agent call
	if err := conn.addVmToAgent(addMsg); err != nil {
		/* Dont fail if agent command fails. Maybe agent is down and will
		 * comeback shortly. When VRouter Agent comes back, PollVM will have
		 * chance to succeed
		 */
		return nil, fmt.Errorf("Agent error adding VM to agent : %s", err)
	}

	return nil, nil
}

/****************************************************************************
 * DEL message handling
 ****************************************************************************/
// Del Message definition
type contrailDelMsg struct {
	Vm string `json:"vm-label"`
	Nw string `json:"network-label"`
}

// Make Del Message call
func makeDelMsg(podName string) *contrailDelMsg {
	delMsg := contrailDelMsg{Vm: podName}
	return &delMsg
}

// Del VM config file
func (conn *Connection) delVmToFile(delMsg *contrailDelMsg) error {
	fname := conn.makeFileName()
	_, err := os.Stat(fname)
	// File not present... noting to do
	if err != nil {
		return fmt.Errorf("File %s not found. Error %s", fname, err)
	}

	// Delete file
	err = os.Remove(fname)
	if err != nil {
		return fmt.Errorf("Error deleting file %s. Error %s", fname, err)
	}

	return nil
}

func (conn *Connection) delVmToAgent(delMsg *contrailDelMsg) error {
	msg, err := json.MarshalIndent(delMsg, "", "\t")
	if err != nil {
		return fmt.Errorf("Error framing delete message %s", err)
	}

	resp, err := conn.doOp("DELETE", true, msg)
	if err != nil {
		return fmt.Errorf("Error in DELETE operation. %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Agent returned error for VM DElETE message. Code : ",
			resp.StatusCode)
	}
	return nil
}

/* Process delete VM. The method ignores intermediate errors and does best
 * effort cleanup
 */
func (conn *Connection) DelVm(podName string) error {
	// Make del message structure
	delMsg := makeDelMsg(podName)

	var ret error
	// Remove the configuraion file stored for persistency
	if err := conn.delVmToFile(delMsg); err != nil {
		ret = fmt.Errorf("Agent Error deleting config file : %s", err)
	}

	// Make the del message calll to agent
	if err := conn.delVmToAgent(delMsg); err != nil {
		ret = fmt.Errorf("Agent error deleting VM to agent : %s", err)
	}

	return ret
}

/****************************************************************************
 * POLL message handling
 ****************************************************************************/
type Result struct {
	Vm   string `json:"vm"`
	Ip   string `json:"ip-address"`
	Plen int    `json:"plen"`
	Gw   string `json:"gateway"`
	Dns  string `json:"dns-server"`
	Mac  string `json:"mac-address"`
}

type contrailGetMsg struct {
	vm string `json:"vm"`
}

func initPollVmReq(instanceId string) *contrailGetMsg {
	return &contrailGetMsg{vm: instanceId}
}

func (conn *Connection) pollVmOnce(instanceId string) (*Result, error) {
	delMsg := initPollVmReq(instanceId)
	msg, err := json.MarshalIndent(delMsg, "", "\t")
	if err != nil {
		return nil, err
	}

	resp, err := conn.doOp("GET", true, msg)
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
	var msg string
	for i := 0; i < count; i++ {
		result, err := conn.pollVmOnce(instanceId)
		if err == nil {
			return result, nil
		}

		msg = err.Error()
		var d time.Duration
		d, err = time.ParseDuration(delay)
		if err != nil {
			d, err = time.ParseDuration(delay)
		}

		time.Sleep(d)
	}

	return nil, fmt.Errorf("Failed in PollVM for instance %s. Error %s",
		instanceId, msg)
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
		return nil, fmt.Errorf("Agent Error : Directory name not specified")
	}

	httpClient := new(http.Client)
	conn := Connection{server: server, port: port, vm: vm, dir: dir,
		httpClient: httpClient}
	return &conn, nil
}
