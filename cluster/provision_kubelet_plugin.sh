#!/bin/bash
#######################################################################
# opencontrail-kubernetes kubelet plugin setup and provisioning script. 
# For more info, please refer to the following link
# https://github.com/Juniper/contrail-kubernetes
#
# Author - Sanju Abraham -@asanju- OpenContrail-Kubernetes
#
#######################################################################
set -x

readonly PROGNAME=$(basename "$0")

ockver=$OPENCONTRAIL_KUBERNETES_TAG

timestamp() {
    date
}

if [ ! -f /var/log/contrail/provision_kubelet_plugin.log ]; then
   mkdir -p /var/log/contrail
   touch /var/log/contrail/provision_kubelet_plugin.log
fi

log_error_msg() {
    msg=$1
    echo "$(timestamp): ERROR: $msg"
}

log_warn_msg() {
    msg=$1
    echo "$(timestamp): WARNING: $msg"
}

log_info_msg() {
    msg=$1
    echo "$(timestamp): INFO: $msg"
}

log_info_msg "Start Provisioning kubelet for opencontrail"

LOG_FILE=/var/log/contrail/provision_kubelet_plugin.log
exec 2>&1 &> >(tee -a "$LOG_FILE")

REDHAT="redhat"
UBUNTU="ubuntu"
VROUTER="vrouter"

if [[ -z $ockver ]]; then
   ockver="master"
fi

hname=`hostname`

function persist_hostname()
{
   if [ ! -f /etc/hostname ]; then
     echo "$hname" > /etc/hostname
     hostname $hname
   fi
}

function detect_os()
{
   OS=`uname`
   OS_TYPE="none"
   if [ "${OS}" = "Linux" ]; then
      if [ -f /etc/redhat-release ]; then
         OS_TYPE="redhat"
      elif [ -f /etc/debian_version ]; then
         OS_TYPE="ubuntu"
      fi
   fi
}

function prep_to_install()
{
  if [ "$OS_TYPE" == $REDHAT ]; then
    yum update
    yum install -y python-pip python-setuptools aufs-tools
  elif [ "$OS_TYPE" == $UBUNTU ]; then
    apt-get update
    apt-get install -y python-pip python-setuptools aufs-tools
  fi
}

function setup_opencontrail_kubelet()
{
  ockub=$(pip freeze | grep kubelet | awk -F= '{print $1}')
  if [ ! -z "$ockub" ]; then
     pip uninstall -y opencontrail-kubelet
  fi
  (exec pip install --upgrade opencontrail-kubelet)
  
  mkdir -p /usr/libexec/kubernetes/kubelet-plugins/net/exec/opencontrail
  if [ ! -f /usr/libexec/kubernetes/kubelet-plugins/net/exec/opencontrail/config ]; then
     touch /usr/libexec/kubernetes/kubelet-plugins/net/exec/opencontrail/config
  fi
  config="/usr/libexec/kubernetes/kubelet-plugins/net/exec/opencontrail/config"
  ocp="/usr/local/bin/opencontrail-kubelet-plugin"
  if [ ! -f "$ocp" ]; then
     log_info_msg "Opencontrail-kubelet-plugin not found. Please check the package opencontrail-kubelet"
     exit 1
  fi
  grep -q 'DEFAULTS' $config || echo "[DEFAULTS]" >> $config
  sed -i '/api_server/d' $config
  echo "api_server=$OPENCONTRAIL_CONTROLLER_IP" >> $config
  (cd /usr/libexec/kubernetes/kubelet-plugins/net/exec/opencontrail; `ln -s $ocp opencontrail`) && cd
}

function main()
{
   persist_hostname
   detect_os
   prep_to_install
   setup_opencontrail_kubelet
   log_info_msg "Provisioning of opencontrail-kubelet-plugin completed."
}

main
