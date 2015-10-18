#!/bin/bash

set -ex
set -o pipefail

LOG_FILE=/var/log/contrail/provision_master.log
mkdir -p /var/log/contrail
exec 1<&- # Close STDOUT file descriptor
exec 2<&- # Close STDERR FD
exec 1<>$LOG_FILE # Open STDOUT as $LOG_FILE file for read and write.
exec 2>&1 # Redirect STDERR to STDOUT

# contrail-kubernetes setup and provisioning script. For more info, please refer to
# https://github.com/Juniper/contrail-kubernetes

# Retry a command $RETRY times with $WAIT seconds delay in between
function retry() {
    set +e

    CMD=$1
    echo $CMD
    shift

    if [ -z $RETRY ]; then
        RETRY=10
    fi
    if [ -z $WAIT ]; then
        WAIT=10
    fi

    COUNTER=0
    while [  $COUNTER -lt $RETRY ]; do
        $CMD $*
        if [ "$?" = "0" ]; then
            return
        fi
        let COUNTER=COUNTER+1
        echo Try again $COUNTER/$RETRY
        sleep $WAIT
    done

    set -e

    echo "Error EXIT: $CMD $* Failed with exit code $?"
    exit -1
}

# Run a command in kubernetes-master node
function master() {
    bash -c "sudo $*"
}

function isGceVM()
{
  if [ -f /var/run/google.onboot ]; then
   return 0
  else
   return 1
  fi
}

# Verify that contrail infra components are up and listening
function verify_contrail_listen_services() {
    RETRY=20
    WAIT=3
    retry master 'netstat -anp | grep LISTEN | grep -w 5672' # RabbitMQ
    retry master 'netstat -anp | grep LISTEN | grep -w 2181' # ZooKeeper
    retry master 'netstat -anp | grep LISTEN | grep -w 9160' # Cassandra
    retry master 'netstat -anp | grep LISTEN | grep -w 5269' # XMPP Server
    retry master 'netstat -anp | grep LISTEN | grep -w 8083' # Control-Node
    retry master 'netstat -anp | grep LISTEN | grep -w 8443' # IFMAP
    retry master 'netstat -anp | grep LISTEN | grep -w 8082' # API-Server
    retry master 'netstat -anp | grep LISTEN | grep -w 8087' # Schema
    retry master 'netstat -anp | grep LISTEN | grep -w 8086' # Collector
    retry master 'netstat -anp | grep LISTEN | grep -w 8081' # OpServer
    retry master 'netstat -anp | grep LISTEN | grep -w 8091' # query-engine
    retry master 'netstat -anp | grep LISTEN | grep -w 6379' # redis
    retry master 'netstat -anp | grep LISTEN | grep -w 8143' # WebUI
    retry master 'netstat -anp | grep LISTEN | grep -w 8070' # WebUI
    retry master 'netstat -anp | grep LISTEN | grep -w 3000' # WebUI
#   retry master 'netstat -anp | grep LISTEN | grep -w 5998' # discovery
#   retry master 'netstat -anp | grep LISTEN | grep -w 8094' # dns
#   retry master 'netstat -anp | grep LISTEN | grep -w 53'   # named
}

# Check for internal statemachines of API and contrail-control
# and restart if not set
function check_contrail_services()
{
  apt-get install -y libxml2-utils host
  vr=''
  for (( i=0; i<20; i++ ))
    do
     vr=$(curl -s http://localhost:8082 | grep -ow "virtual-routers")
     if [ ! -z "$vr" ]; then
       break
     fi
     sleep 3
    done
   if [ "$vr" != "virtual-routers" ]; then
     echo "Debug: Contrail-API initialization failure. Restart once"
     docker restart `docker ps | grep -v pause | grep contrail-api | awk '{print $1}'`
   fi

  cc=''
  ifmapup=false
  for (( i=0; i<5; i++ ))
    do
     cc=$(curl -s http://$OPENCONTRAIL_CONTROLLER_IP:8083/Snh_SandeshUVECacheReq?tname=NodeStatus | xmllint --format - | grep -ow "contrail-control")
     if [ ! -z $cc ]; then
         ifmapup=$(curl -s http://$OPENCONTRAIL_CONTROLLER_IP:8083/Snh_IFMapPeerServerInfoReq? | xmllint --format - | grep end_of_rib_computed | cut -d ">" -f2 | cut -d "<" -f1)
     fi
     if [ "$ifmapup" == true ]; then
       log_info_msg "IFMAP and Contrail-Control are up are ready for processing agent subscriptions"
       break
     fi
     sleep 3
    done
  if ! $ifmapup ; then
     echo "Debug: Contrail-Control intialization failure. Restart once"
     docker restart `docker ps | grep -v pause | grep contrail-control | awk '{print $1}'`
  fi
}

# Provision controller
function provision_controller() {
    cmd='docker ps | grep contrail-api | grep -v pause | awk "{print \"docker exec \" \$1 \" python /usr/share/contrail-utils/provision_control.py  --router_asn 64512 --host_name `hostname` --host_ip `hostname --ip-address` --oper add --api_server_ip `hostname --ip-address` --api_server_port 8082\"}" | sudo sh'
    master $cmd
}

# Provision link local service
function provision_linklocal() {
    cmd='docker ps | grep contrail-api | grep -v pause | awk "{print \"docker exec \" \$1 \" python /usr/share/contrail-utils/provision_linklocal.py --api_server_ip `hostname --ip-address` --api_server_port 8082 --linklocal_service_name kubernetes-dns-ssl --linklocal_service_ip 10.0.0.1 --linklocal_service_port 443 --ipfabric_service_ip `hostname --ip-` --ipfabric_service_port 443 --oper add\"}" | sudo sh'
    master $cmd
}

# Provision vrouter encap order
function provision_vrouter_encap() {
    if isGceVM ; then
       cmd='docker ps | grep contrail-api | grep -v pause | awk "{print \"docker exec \" \$1 \" python /usr/share/contrail-utils/provision_encap.py --api_server_ip `hostname --ip-address` --api_server_port 8082 --encap_priority MPLSoUDP --admin_user myuser --admin_password mypass --oper add\"}" | sudo sh'
    else
       cmd='docker ps | grep contrail-api | grep -v pause | awk "{print \"docker exec \" \$1 \" python /usr/share/contrail-utils/provision_encap.py --api_server_ip `hostname --ip-address` --api_server_port 8082 --encap_priority MPLSoUDP,MPLSoGRE,VXLAN --admin_user myuser --admin_password mypass --oper add\"}" | sudo sh'
    fi
    master $cmd
}

# Setup kube dns
function setup_kube_dns() {
  master /bin/sed -i '/kube_master_url/d' /etc/kubernetes/addons/dns/skydns-rc.yaml
  master /usr/local/bin/kubectl --namespace=kube-system delete rc kube-dns-v9
  master /usr/local/bin/kubectl  create -f /etc/kubernetes/addons/dns/skydns-rc.yaml || true
}

# Setup kube dns endpoints
function setup_kube_dns_endpoints() {
    master /usr/local/bin/kubectl --namespace=kube-system delete service kube-ui
    master /usr/local/bin/kubectl --namespace=kube-system create -f /etc/kubernetes/addons/kube-ui/kube-ui-svc.yaml || true
    master /usr/local/bin/kubectl --namespace=kube-system delete rc kube-ui-v2
    master /usr/local/bin/kubectl --namespace=kube-system create -f /etc/kubernetes/addons/kube-ui/kube-ui-rc.yaml || true
}

function check_docker()
{
  cbr=$(cat /etc/default/kubelet | grep -ow "configure-cbr0=true" | cut -d= -f 2)
  if [ "$cbr" == true ]; then
      kubeletpid=$(ps -ef|grep "kubelet --enable-debugging-handlers" | grep -v grep | awk '{print $2}')
      if [ -z "$kubeletpid" ]; then
         service kubelet restart
      fi
  else
    docpid=docpid=$(ps -ef|grep "docker -d" | grep -v grep | awk '{print $2}')
    if [ -z "$docpid" ]; then
      (/usr/bin/docker -d -p /var/run/docker.pid --bridge=cbr0 --iptables=false --ip-masq=false)&
    fi
  fi
}

# Setup contrail manifest files under kubernetes
function setup_contrail_manifest_files() {
    mkdir -p /etc/contrail
    echo "[IFMAP]" >> /etc/contrail/contrail-control.conf
    echo "server_url=https://127.0.0.1:8443" >> /etc/contrail/contrail-control.conf

    mkdir -p /etc/kubernetes
    echo "[DEFAULT]" > /etc/kubernetes/network.conf
    echo "service-cluster-ip-range = $SERVICE_CLUSTER_IP_RANGE" >> /etc/kubernetes/network.conf

    echo >> /etc/kubernetes/network.conf
    echo "[opencontrail]" >> /etc/kubernetes/network.conf
    echo "public-ip-range = $OPENCONTRAIL_PUBLIC_SUBNET" >> /etc/kubernetes/network.conf
    echo "private-ip-range = 10.10.0.0/16" >> /etc/kubernetes/network.conf
    echo "cluster-service  = kube-system/default" >> /etc/kubernetes/network.conf

    cmd1='wget -qO - https://raw.githubusercontent.com/juniper/contrail-kubernetes/'
    cmd2='/cluster/manifests.hash | grep -v contrail-vrouter-agent | grep -v provision | awk "{print \"https://raw.githubusercontent.com/juniper/contrail-kubernetes/'
    cmd3='/cluster/\"\$1}" | xargs -n1 sudo wget -q --directory-prefix=/etc/contrail/manifests --continue'
    cmd="$cmd1$OPENCONTRAIL_KUBERNETES_TAG$cmd2$OPENCONTRAIL_KUBERNETES_TAG$cmd3"
    master $cmd

    #check_docker
    cmd='grep \"image\": /etc/contrail/manifests/* | cut -d "\"" -f 4 | sort -u | xargs -n1 sudo docker pull'
    RETRY=20
    WAIT=3
    retry master $cmd
    #check_docker
    cmd='mv /etc/contrail/manifests/* /etc/kubernetes/manifests/'
    master $cmd
}

# Provision config
function setup_opencontrail_config() {
    cmd='docker ps | grep contrail-api | grep -v pause | awk "{print \"docker exec \" \$1 \" python /usr/share/contrail-utils/provision_config_node.py --api_server_ip `hostname --ip-address` --host_name `hostname` --host_ip `hostname --ip-address` --oper add  --admin_user admin --admin_password contrail123 --admin_tenant_name kube-system\"}" | sudo sh'
    master $cmd
}

# Provision database
function setup_opencontrail_database() {
    cmd='docker ps | grep contrail-api | grep -v pause | awk "{print \"docker exec \" \$1 \" python /usr/share/contrail-utils/provision_database_node.py --api_server_ip `hostname --ip-address` --host_name `hostname` --host_ip `hostname --ip-address` --oper add  --admin_user admin --admin_password contrail123 --admin_tenant_name kube-system\"}" | sudo sh'
    master $cmd
}

# Provision analytics
function setup_opencontrail_analytics() {
    cmd='docker ps | grep contrail-api | grep -v pause | awk "{print \"docker exec \" \$1 \" python /usr/share/contrail-utils/provision_analytics_node.py --api_server_ip `hostname --ip-address` --host_name `hostname` --host_ip `hostname --ip-address` --oper add  --admin_user admin --admin_password contrail123 --admin_tenant_name kube-system\"}" | sudo sh'
    master $cmd
}

# Setup contrail-controller components
function setup_contrail_master() {

    # Pull all contrail images and copy the manifest files
    setup_contrail_manifest_files

    # Wait for contrail-control to be ready.
    verify_contrail_listen_services

    # Check for internal states of API and contrail-control
    check_contrail_services

    # Provision controller
    provision_controller

    # Provision link-local service to connect to kube-api
    provision_linklocal

    # Provision vrouter encap order
    provision_vrouter_encap

    # Setip kube-dns
    setup_kube_dns
    setup_kube_dns_endpoints

    # provision
    setup_opencontrail_config
    setup_opencontrail_database
    setup_opencontrail_analytics
}

setup_contrail_master
