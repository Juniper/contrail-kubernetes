FROM golang:1.5
MAINTAINER Pedro Marques <roque@juniper.net>
RUN mkdir -p src/github.com/Juniper
RUN (cd src/github.com/Juniper && git clone https://github.com/Juniper/contrail-go-api -b 1.0.0)
RUN wget https://github.com/Juniper/contrail-go-api/releases/download/1.0.0/contrail-go-api-generated-types-r2.20.tar.gz
RUN (cd src && tar zxvf ../contrail-go-api-generated-types-r2.20.tar.gz)
RUN mkdir -p src/k8s.io
RUN (cd src/k8s.io && git clone https://github.com/kubernetes/kubernetes.git)
