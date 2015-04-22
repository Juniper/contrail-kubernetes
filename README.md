# contrail-kubernetes
OpenContrail Kubernetes integration

Proof of concept.

The command kube-network-manager uses the user labels{'name', 'uses'} in order to create a network per pod/RC/service and create connectivity between networks.

Build:
```
GOPATH=$GOPATH:${GOROOT}/src/github.com/GoogleCloudPlatform/kubernetes/Godeps/_workspace

go build github.com/Juniper/contrail-kubernetes/pkg/network
go build github.com/Juniper/contrail-kubernetes/cmd/kube-network-manager
```
