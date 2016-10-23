#/bin/bash
#ip netns add TestNS
export GOPATH=$HOME/k8s/lib
export CNI_COMMAND=$1
export CNI_NETNS="/var/run/netns/TestNS"
export CNI_IFNAME="eth0"
export CNI_PATH="/test"
export CNI_CONTAINERID="1234"
export CNI_ARGS="IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=hello-world-1-81nl8;K8S_POD_INFRA_CONTAINER_ID=4209d77cedfc320540b55d52a7d19b3c5f8cb99e29ed9842eeb8e426608b0f6a"
$HOME/k8s/go/bin/go run contrail.go < contrail.conf
