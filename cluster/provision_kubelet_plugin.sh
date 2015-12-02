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

runok="/etc/contrail/kubelet_plugin_install.ok"
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
  # aufs-tools is required by docker for auplink during unmout
  if [ "$OS_TYPE" == $REDHAT ]; then
    yum update
    yum install -y python-pip python-setuptools aufs-tools
  elif [ "$OS_TYPE" == $UBUNTU ]; then
    apt-get update
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" --force-yes python-pip python-setuptools aufs-tools
  fi
}

function prereq_install_contrail()
{
  doc=$(which docker)
  if [ "$OS_TYPE" == $REDHAT ]; then
     docon=$(rpm -qa | grep docker)
  elif [ "$OS_TYPE" == $UBUNTU ]; then
     docon=$(dpkg -l | grep docker)
  fi

  if [ -z "$docon" ] && [ -z "$doc" ]; then
     curl -sSL https://get.docker.com/ | sh
     if [ ! -f /usr/bin/docker ]; then
         if [ "$OS_TYPE" == $REDHAT ]; then
            yum update
         elif [ "$OS_TYPE" == $UBUNTU ]; then
            apt-get update --fix-missing
         fi
         curl -sSL https://get.docker.com/ | sh
     fi
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

function kube_manifest_setup()
{
  if [ ! -f /etc/kubernetes/manifests ]; then
     mkdir -p /etc/kubernetes/manifests
  fi
}

function main()
{
   persist_hostname
   detect_os
   prep_to_install
   prereq_install_contrail
   setup_opencontrail_kubelet
   kube_manifest_setup
   log_info_msg "Provisioning of opencontrail-kubelet-plugin completed."
   cdir=`dirname "$runok"`
     if [ ! -f "$cdir" ]; then
       mkdir -p "$cdir"
     fi
   touch $runok
}

main
