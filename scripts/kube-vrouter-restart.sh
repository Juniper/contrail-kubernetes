#!/bin/bash
#
# Run the kubebet plugin script for all running containers in the system.
# This can be run as a PostExec script for the vrouter-agent when running
# on a kubernetes node.
#
KUBE_PLUGIN=/usr/libexec/kubernetes/kubelet-plugins/net/exec/opencontrail/opencontrail

CONTAINERS=$(docker ps | grep -v "/pause" | awk '/[0-9a-z]{12} /{print $1;}')

for i in $CONTAINERS; do
    NAME=$(docker inspect -f '{{.Name}}' $i)
    ID=$(docker inspect -f '{{.Id}}' $i)
    PODNAME=$(echo $NAME | awk '//{split($0, arr, "_"); print arr[3]}')
    NAMESPACE=$(echo $NAME | awk '//{split($0, arr, "_"); print arr[4]}')
    $KUBE_PLUGIN setup $NAMESPACE $PODNAME $ID
done
