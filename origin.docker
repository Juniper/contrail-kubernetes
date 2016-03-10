FROM golang:1.5
MAINTAINER Pedro Marques <roque@juniper.net>
RUN mkdir -p src/github.com/Juniper
RUN (cd src/github.com/Juniper && git clone https://github.com/Juniper/contrail-go-api -b v1.1.0)
RUN wget https://github.com/Juniper/contrail-go-api/releases/download/1.0.0/contrail-go-api-generated-types-r2.20.tar.gz
RUN (cd src && tar zxvf ../contrail-go-api-generated-types-r2.20.tar.gz)
RUN mkdir -p src/github.com/openshift
RUN (cd src/github.com/openshift && git clone https://github.com/openshift/origin -b v1.1.3)
RUN mkdir -p src/github.com/Juniper/contrail-kubernetes
ADD cmd /go/src/github.com/Juniper/contrail-kubernetes/cmd
ADD pkg /go/src/github.com/Juniper/contrail-kubernetes/pkg
RUN GOPATH=$GOPATH:$GOPATH/src/github.com/openshift/origin/Godeps/_workspace go build github.com/Juniper/contrail-kubernetes/cmd/kube-network-manager
RUN rm -rf src/github.com
ENTRYPOINT ["/go/kube-network-manager"]
