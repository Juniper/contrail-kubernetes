// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
)

type vmResp struct {
	Vm   string `json:"vm"`
	Ip   string `json:"ip"`
	Plen int    `json:"plen"`
	Gw   string `json:"gw"`
	Dns  string `json:"dns"`
}

type statusResp struct {
	Status string `json:"status"`
}

var addr int = 3

func vmServer(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		log.Println("GET request")
		ip := "1.1.1." + strconv.Itoa(addr)
		addr += 1
		resp := vmResp{Vm: "VM", Ip: ip, Plen: 24, Gw: "1.1.1.1",
			Dns: "1.1.1.2"}
		msg, _ := json.Marshal(resp)
		io.WriteString(w, string(msg))
		return
	}

	if req.Method == "POST" {
		log.Println("POST request")
		resp := statusResp{Status: "OK"}
		msg, _ := json.Marshal(resp)
		io.WriteString(w, string(msg))
		return
	}

	if req.Method == "DELETE" {
		log.Println("DELETE request")
		resp := statusResp{Status: "OK"}
		msg, _ := json.Marshal(resp)
		io.WriteString(w, string(msg))
		return
	}

	io.WriteString(w, "Hello World\n")
}

func main() {
	http.HandleFunc("/vm/", vmServer)
	http.ListenAndServe(":9090", nil)
}
