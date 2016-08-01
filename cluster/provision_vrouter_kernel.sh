#!/bin/bash
##############################################################
# opencontrail-kubernetes vrouter kernel mod builder 
# For more info, please refer to the following link
# https://github.com/Juniper/contrail-kubernetes
#
# Author - Sanju Abraham -@asanju- OpenContrail-Kubernetes
#
##############################################################
set -x

readonly PROGNAME=$(basename "$0")

runok="/etc/contrail/vrouter_kmod.ok"
ocver=$OPENCONTRAIL_TAG
VROUTER="vrouter"
VROUTER_DKMB_IMG=""
VROUTER_DKMB="vrouter-dkmb"
vrkmoddocid=""

timestamp() {
    date
}

if [ ! -f /var/log/contrail/provision_vrouter_kmod.log ]; then
   mkdir -p /var/log/contrail
   touch /var/log/contrail/provision_vrouter_kmod.log
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

log_info_msg "Start building VROUTER kernel module"

LOG_FILE=/var/log/contrail/provision_vrouter_kmod.log
exec 2>&1 &> >(tee -a "$LOG_FILE")

REDHAT="redhat"
UBUNTU="ubuntu"

if [[ -z $ocver ]]; then
   ocver="R2.20"
fi

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

# Revisit this when docker build 
# supports environment variables
# This model supports different 
# versions and OS
function launch_docker()
{
  if [ "$OS_TYPE" == "$UBUNTU" ]; then
     os=$(lsb_release -d | awk '{print tolower($2)}')
     oscode=$(lsb_release -c | awk '{print tolower($2)}')
     rel=$(lsb_release -r | awk '{print $2}')
     if [ "$os" == "debian" ] && [ "$rel" == "7.9" ]; then
         rel="wheezy-backports"
     fi
  elif [ "$OS_TYPE" == "REDHAT" ]; then
         os=$(cat /etc/redhatrelease | awk '{print tolower($1)}')
         rel=$(cat /etc/redhatrelease | awk '{print $3}')
  fi
  img=$os:$rel
  VROUTER_DKMB_IMG=$img
  docker_pull $img $rel
  sleep 2
  docker run --privileged -d -P --name $VROUTER_DKMB --net="host" -v /lib:/lib -v /usr/bin:/usr/bin -t -i $img
  sleep 3
  vrkmoddocid=$(docker ps | grep $VROUTER_DKMB | awk '{print $1}')
}

function docdo()
{
  cmd=$1
  execCmd="docker exec -it $vrkmoddocid"
  $execCmd bash -c "$1"
}

function docker_pull()
{
  img=$1
  rel=$2
  (echo $img | xargs -n1 sudo docker pull) & pullpid=$!
  i=0
  while true
    do
      dvrimg=$(docker images | grep -iow $rel)
      if [ ! -z  "$dvrimg" ]; then
         break
      fi
      sleep 2
      ((i++))
      if [ $i -eq 5 ]; then
       if [ -d "/proc/${pullpid}" ]; then
          pkill -TERM -P $pullpid
          cnt=$(ps -ef|grep "docker pull" | grep $img | wc -l)
          if [ $cnt -gt 1 ]; then
             log_info_msg "Restarting docker and retrying pull of image"
             service docker restart
          fi
       fi
       # give time for docker to initialize
       sleep 60
       log_info_msg "pulling of image was not successful in the initial attempt."
       (echo $img | xargs -n1 sudo docker pull) & pullpid=$!
       i=0
      fi
    done
}

function prereq_vrouter()
{
  if [ "$OS_TYPE" == $REDHAT ]; then
     docon=$(rpm -qa | grep docker)
  elif [ "$OS_TYPE" == $UBUNTU ]; then
     docon=$(dpkg -l | grep docker)
  fi

  if [ -z "$docon" ]; then
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

function prep_to_install()
{
  if [ "$OS_TYPE" == $REDHAT ]; then
    docdo "yum update"
    docdo "yum install -y git make automake flex bison gcc gcc-c++ boost boost-devel scons kernel-devel-`uname -r`"
  elif [ "$OS_TYPE" == $UBUNTU ]; then
    docdo "apt-get update --fix-missing"
    # in case of an interrupt during execution of apt-get
    docdo "dpkg --configure -a"
    docdo "apt-get install -y git make automake flex bison g++ gcc make libboost-all-dev scons linux-headers-`uname -r`"
  fi
}

function build_vrouter()
{
  docdo "mkdir -p ~/vrouter-build/tools"
  docdo "cd ~/vrouter-build && (git clone -b $ocver https://github.com/Juniper/contrail-vrouter vrouter)"
  docdo "cd ~/vrouter-build/tools && (git clone https://github.com/Juniper/contrail-build build)"
  docdo "cd ~/vrouter-build/tools && (git clone -b $ocver https://github.com/Juniper/contrail-sandesh sandesh)"
  docdo "cp ~/vrouter-build/tools/build/SConstruct ~/vrouter-build"
  docdo "cd ~/vrouter-build && USER=opencontrail scons --optimization=production vrouter 2>&1"
}

function modprobe_vrouter()
{
  vr=$(lsmod | grep vrouter | awk '{print $1}')
  if [ "$vr" == $VROUTER ]; then
    if [ "$OS_TYPE" == $REDHAT ]; then
        rm -rf /lib/modules/`uname -r`/extra/net/vrouter
    elif [ "$OS_TYPE" == $UBUNTU ]; then
        rm -rf /lib/modules/`uname -r`/updates/dkms/vrouter.ko
    fi
  fi
  #Fresh install
  if [ "$OS_TYPE" == $REDHAT ]; then
     mkdir -p /lib/modules/`uname -r`/extra/net/vrouter
     docdo "mv ~/vrouter-build/vrouter/vrouter.ko /lib/modules/`uname -r`/extra/net/vrouter"
  elif [ "$OS_TYPE" == $UBUNTU ]; then
      mkdir -p /lib/modules/`uname -r`/updates/dkms
      docdo "mv ~/vrouter-build/vrouter/vrouter.ko /lib/modules/`uname -r`/updates/dkms"
  fi
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/vif /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/rt /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/dropstats /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/flow /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/mirror /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/mpls /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/nh /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/vxlan /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/vrfstats /usr/bin"
  docdo "mv ~/vrouter-build/build/production/vrouter/utils/vrouter /usr/bin"
  cd /lib/modules/`uname -r` && depmod && cd
  `modprobe vrouter`
  vr=$(lsmod | grep vrouter | awk '{print $1}')
  if [ "$vr" == $VROUTER ]; then
     log_info_msg "Latest version of Opencontrail kernel module - $vr instaled"
  else
     log_info_msg "Installing Opencontrail kernel module - $vr failed"
  fi 
}

function check_kmod()
{
  vr=$(lsmod |grep -ow vrouter)
  if [ ! -z $vr ]; then
     cdir=`dirname "$runok"`
     if [ ! -f "$cdir" ]; then
       mkdir -p "$cdir"
     fi
     touch $runok
     log_info_msg "vrouter kernel module successfully build and installed"
  fi
}

# This is to support VM images that
# dont ahve docker support in the base image
function configure-cgroup() {
  echo "=== checking grub config for cgroup ==="
  cg=$(cat /etc/default/grub  | grep swapaccount)
  if [[ -z "$cg" ]]; then
     source /etc/default/grub
     grubstr='GRUB_CMDLINE_LINUX_DEFAULT="'"$GRUB_CMDLINE_LINUX_DEFAULT cgroup_enable=memory swapaccount=1"'"'
     sed -i '/GRUB_CMDLINE_LINUX_DEFAULT/d' /etc/default/grub
     echo $grubstr >> /etc/default/grub
     sudo update-grub
     reboot
  fi
}

function cleanup()
{
  docker stop $VROUTER_DKMB
  docker rm $VROUTER_DKMB
  docker rmi $VROUTER_DKMB_IMG
}

function main()
{
   detect_os
   configure-cgroup
   prereq_vrouter
   launch_docker
   prep_to_install
   build_vrouter
   modprobe_vrouter
   check_kmod
   cleanup
}

main
