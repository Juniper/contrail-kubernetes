FROM opencontrail/go-k8s-builder
MAINTAINER Pedro Marques <roque@juniper.net>
RUN mkdir -p src/github.com/Juniper/contrail-kubernetes
ADD cmd /go/src/github.com/Juniper/contrail-kubernetes/cmd
ADD pkg /go/src/github.com/Juniper/contrail-kubernetes/pkg
RUN GOPATH=$GOPATH:$GOPATH/src/k8s.io/kubernetes/Godeps/_workspace go build github.com/Juniper/contrail-kubernetes/cmd/kube-network-manager
RUN rm -rf src/github.com
ENTRYPOINT ["/go/kube-network-manager"]
