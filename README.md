# contrail-kubernetes
![Build Status](https://travis-ci.org/Juniper/contrail-kubernetes.svg)
[![Coverage Status](https://coveralls.io/repos/Juniper/contrail-kubernetes/badge.svg?branch=master&service=github)](https://coveralls.io/github/Juniper/contrail-kubernetes?branch=master)

OpenContrail Kubernetes integration

The daemon kube-network-manager uses the kubernetes controller framework to watch k8s api objects. It isolates pods in virtual-networks (according to the label['name']) and connects pods with services (according to the label['uses']).

Build:
```
GOPATH=$GOPATH:${GOROOT}/src/github.com/GoogleCloudPlatform/kubernetes/Godeps/_workspace

go build github.com/Juniper/contrail-kubernetes/cmd/kube-network-manager
```
