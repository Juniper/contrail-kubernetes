# contrail-kubernetes

[![Join the chat at https://gitter.im/Juniper/contrail-kubernetes](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/Juniper/contrail-kubernetes?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/Juniper/contrail-kubernetes.svg?branch=master)](https://travis-ci.org/Juniper/contrail-kubernetes)
[![Coverage Status](https://coveralls.io/repos/Juniper/contrail-kubernetes/badge.svg?branch=master&service=github)](https://coveralls.io/github/Juniper/contrail-kubernetes?branch=master)

OpenContrail Kubernetes integration

The daemon kube-network-manager uses the kubernetes controller framework to watch k8s api objects. It isolates pods in virtual-networks (according to the label['name']) and connects pods with services (according to the label['uses']).

Build:
```
GOPATH=$GOPATH:${GOROOT}/src/k8s.io/kubernetes/Godeps/_workspace

go build github.com/Juniper/contrail-kubernetes/cmd/kube-network-manager
```
