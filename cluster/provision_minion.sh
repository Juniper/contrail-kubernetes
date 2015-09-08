#!/bin/bash

##############################################################
# opencontrail-kubernetes minion setup and provisioning script. 
# For more info, please refer to the following link
# https://github.com/Juniper/contrail-kubernetes
##############################################################
source /etc/contrail/opencontrail-rc

readonly PROGNAME=$(basename "$0")

ocver=$1

timestamp() {
    date
}

if [ ! -f /var/log/contrail/provision_minion.log ]; then
   mkdir -p /var/log/contrail
   touch /var/log/contrail/provision_minion.log
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

log_info_msg "Start Provisioning VROUTER kernel module and agent in container"

LOG_FILE=/var/log/contrail/provision_minion.log
exec 2>&1 &> >(tee -a "$LOG_FILE")

OS_TYPE="none"
REDHAT="redhat"
UBUNTU="ubuntu"
VROUTER="vrouter"
VHOST="vhost0"

if [[ -z $ocver ]]; then
   ocver="R2.20"
fi

flag=false
rcfile="/etc/contrail/opencontrail-rc"
rcdir=`dirname "$rcfile"`
if [ ! -f "$rcdir" ]; then
    mkdir -p "$rcdir"
fi
if [[ -z $OPENCONTRAIL_CONTROLLER_IP ]]; then
   kube_api_port=$(cat /etc/default/kubelet | grep -o 'api-servers=[^;]*' | awk -F// '{print $2}' | awk '{print $1}')
   kube_api_ip=$(echo $kube_api_port| awk -F':' '{print $1}')
   OPENCONTRAIL_CONTROLLER_IP=$kube_api_ip
   echo "OPENCONTRAIL_CONTROLLER_IP=$kube_api_ip" >> $rcfile
fi
if [[ -z $OPENCONTRAIL_VROUTER_INTF ]];then
   OPENCONTRAIL_VROUTER_INTF="eth0"
   echo "OPENCONTRAIL_VROUTER_INTF="eth0"" >> $rcfile
   flag=true
fi

if [[ "$flag" == true ]]; then
   source "$rcfile"
fi

MINION_OVERLAY_NET_IP=$(/sbin/ifconfig $OPENCONTRAIL_VROUTER_INTF | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}')
if [ -z $MINION_OVERLAY_NET_IP ]; then
   # Check if vhost is already up with the IP
   MINION_OVERLAY_NET_IP=$(ip a | grep vhost0 | grep inet | awk -F/ '{print $1}' | awk '{print $2}')
fi
if [ -z $MINION_OVERLAY_NET_IP ]; then
     msg="Unable to get an IP address on the $OPENCONTRAIL_VROUTER_INTF or vhost0 interface.
         Please check the interface and IP address assignement and restart provision"
    log_error_msg "$msg"
    echo "$msg"
    exit
fi

function detect_os()
{
   OS=`uname`
   if [ "${OS}" = "Linux" ]; then
      if [ -f /etc/redhat-release ]; then
         OS_TYPE="redhat"
      elif [ -f /etc/debian_version ]; then
         OS_TYPE="ubuntu"
      fi
   fi
}

function prep_to_build()
{
  if [ "$OS_TYPEi" == $REDHAT ]; then
    yum update
    yum install -y git make automake flex bison gcc gcc-c++ boost boost-devel scons kernel-devel-`uname -r` libxml2-devel python-lxml sipcalc wget
  elif [ "$OS_TYPE" == $UBUNTU ]; then
    apt-get update
    # in case of an interrupt during execution of apt-get
    dpkg --configure -a
    apt-get install -y git make automake flex bison g++ gcc make libboost-all-dev scons linux-headers-`uname -r` libxml2-dev python-lxml sipcalc wget
  fi
}

function build_vrouter()
{
  rm -rf ~/vrouter-build
  mkdir -p ~/vrouter-build/tools
  cd ~/vrouter-build && `git clone -b $ocver https://github.com/Juniper/contrail-vrouter vrouter`
  cd ~/vrouter-build/tools && `git clone https://github.com/Juniper/contrail-build build`
  cd ~/vrouter-build/tools && `git clone -b $ocver https://github.com/Juniper/contrail-sandesh sandesh`
  cp ~/vrouter-build/tools/build/SConstruct ~/vrouter-build
  cd ~/vrouter-build && scons vrouter 2>&1
}

function modprobe_vrouter()
{
  vr=$(lsmod | grep vrouter | awk '{print $1}')
  phy_itf=$(ip a |grep $MINION_OVERLAY_NET_IP | awk '{print $7}')
  def=$(ip route  | grep $OPENCONTRAIL_VROUTER_INTF | grep -o default)
  if [ "$vr" == $VROUTER ]; then
    if [ "$def" != "default" ] && [ "$phy_itf" != $VHOST ]; then
      `rmmod vrouter`
    fi
    if [ "$OS_TYPE" == $REDHAT ]; then
        rm -rf /lib/modules/`uname -r`/extra/net/vrouter
    elif [ "$OS_TYPE" == $UBUNTU ]; then
        rm -rf /lib/modules/`uname -r`/updates/dkms/vrouter.ko
    fi
  fi
  #Fresh install
  if [ "$OS_TYPE" == $REDHAT ]; then
     mkdir -p /lib/modules/`uname -r`/extra/net/vrouter
     mv ~/vrouter-build/vrouter/vrouter.ko /lib/modules/`uname -r`/extra/net/vrouter
  elif [ "$OS_TYPE" == $UBUNTU ]; then
      mkdir -p /lib/modules/`uname -r`/updates/dkms
      mv ~/vrouter-build/vrouter/vrouter.ko /lib/modules/`uname -r`/updates/dkms
  fi
  mv ~/vrouter-build/build/debug/vrouter/utils/vif /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/rt /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/dropstats /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/flow /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/mirror /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/mpls /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/nh /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/vxlan /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/vrfstats /usr/bin
  mv ~/vrouter-build/build/debug/vrouter/utils/vrouter /usr/bin
  cd /lib/modules/`uname -r` && depmod && cd
  `modprobe vrouter`
  vr=$(lsmod | grep vrouter | awk '{print $1}')
  if [ "$vr" == $VROUTER ]; then
     log_info_msg "Latest version of Opencontrail kernel module - $vr instaled"
  else
     log_info_msg "Installing Opencontrail kernel module - $vr failed"
  fi 
}


function setup_vhost()
{
  phy_itf=$(ip a |grep $MINION_OVERLAY_NET_IP | awk '{print $7}')
  if [ "$phy_itf" == $VHOST ]; then
     log_info_msg "MINION_OVERLAY_NET_IP is already on $VHOST. No change required on the this interface"
     return
  fi
  mask=$(ifconfig $phy_itf | grep -i '\(netmask\|mask\)' | awk '{print $4}' | cut -d ":" -f 2)
  mac=$(ifconfig $phy_itf | grep HWaddr | awk '{print $5}')
  def=$(ip route  | grep $OPENCONTRAIL_VROUTER_INTF | grep -o default)
  defgw=$(ip route | grep $OPENCONTRAIL_VROUTER_INTF | grep $def | awk 'NR==1{print $3}')
  if [ "$OS_TYPE" == $REDHAT ]; then
    if [ "$phy_itf" != $VHOST ]; then
      intf="/etc/sysconfig/network-scripts/ifcfg-$phy_itf"
      sed -i '/IPADDR/d' $intf
      sed -i '/NETMASK/d' $intf
      sed -i '/DNS/d' $intf
      grep -q 'NM_CONTROLLED=no' $intf || echo "NM_CONTROLLED=no" >> $intf
    
      # create and configure vhost0
      touch /etc/sysconfig/network-scripts/ifcfg-$VHOST
      ivhost0="/etc/sysconfig/network-scripts/ifcfg-$VHOST"
      grep -q '#Contrail vhost0' $ivhost0 || echo "#Contrail vhost0" >> $ivhost0
      grep -q 'DEVICE=vhost0' $ivhost0 || echo "DEVICE=vhost0" >> $ivhost0
      grep -q 'DEVICETYPE=vhost' $ivhost0 || echo "DEVICETYPE=vhost" >> $ivhost0
      grep -q 'ONBOOT=yes' $ivhost0 || echo "ONBOOT=yes" >> $ivhost0
      grep -q 'BOOTPROTO=none' $ivhost0 || echo "BOOTPROTO=none" >> $ivhost0
      grep -q 'IPV6INIT=no' $ivhost0 || echo "IPV6INIT=no" >> $ivhost0
      grep -q 'USERCTL=yes' || echo "USERCTL=yes" >> $ivhost0
      grep -q 'IPADDR=$MINION_OVERLAY_NET_IP' $ivhost0 || echo "IPADDR=$MINION_OVERLAY_NET_IP" >> $ivhost0
      grep -q 'NETMASK=$mask' $ivhost0 || echo "NETMASK=$mask" >> $ivhost0
      grep -q 'NM_CONTROLLED=no' $ivhost0 || echo "NM_CONTROLLED=no" >> $ivhost0

      # move any routes on intf to vhost0
      if [ -f /etc/sysconfig/network-scripts/route-$phy_itf ]; then
         mv /etc/sysconfig/network-scripts/route-$phy_itf /etc/sysconfig/network-scripts/route-$VHOST
         sed -i 's/'$phy_itf'/'$VHOST'/g' /etc/sysconfig/network-scripts/route-$VHOST
      fi
      if [ "$def" == "default" ]; then
         sed -i '/GATEWAY='$defgw'/d' $intf
         grep -q 'GATEWAY=$defgw' $ivhost0 || echo "GATEWAY=$defgw" >> $ivhost0
      fi
    fi
  elif [ "$OS_TYPE" == $UBUNTU ]; then
     if [ "$phy_itf" != $VHOST ]; then
        itf="/etc/network/interfaces"
        rt=$(cat $itf | grep route |grep $phy_itf)
        rtv=$(sed "s/$phy_itf/$VHOST/g" <<<"$rt")
        if [ "$OPENCONTRAIL_VROUTER_INTF" == "eth0" ]; then
           grep -q "iface eth0 inet manual" $itf || sed -i 's/^iface eth0 inet.*/iface eth0 inet manual \n    pre-up ifconfig eth0 up\n    post-down ifconfig eth0 down/' $itf
        elif [ "$OPENCONTRAIL_VROUTER_INTF" == "eth1" ]; then
           grep -q "iface eth1 inet manual" $itf || sed -i 's/^iface eth1 inet.*/iface eth1 inet manual \n    pre-up ifconfig eth1 up\n    post-down ifconfig eth1 down/' $itf
        elif [ "$OPENCONTRAIL_VROUTER_INTF" == "bond0" ]; then
           grep -q "iface bond0 inet manual" $itf || sed -i 's/^iface bond0 inet.*/iface bond0 inet manual \n    pre-up ifconfig bond0 up\n    post-down ifconfig bond0 down/' $itf
        fi
        grep -vwE "(address $MINION_OVERLAY_NET_IP|netmask $mask)" $itf > /tmp/interface
        mv /tmp/interface $itf
    
        # create and configure vhost0
        grep -q 'auto vhost0' $itf || echo "auto vhost0" >> $itf
        grep -q 'iface vhost0 inet static' $itf || echo "iface vhost0 inet static" >> $itf
        grep -q 'netmask $mask' $itf || echo "    netmask $mask" >> $itf
        grep -q 'address $MINION_OVERLAY_NET_IP' $itf || echo "    address $MINION_OVERLAY_NET_IP" >> $itf
        grep -q 'network_name application' $itf || echo "    network_name application" >> $itf
        if [ "$def" == "default" ]; then
              sed -i '/gateway '$defgw'/d' $itf
              grep -q 'gateway $defgw' $itf || echo "    gateway $defgw" >> $itf
        fi
        grep -q "$rtv" $itf || echo "    $rtv" >> $itf
     fi
  fi   
}

function setup_opencontrail_kubelet()
{
  if [ "$OS_TYPE" == $UBUNTU ]; then
     apt-get install -y python-setuptools
     apt-get install -y python-pip
  elif [ "$OS_TYPE" == $REDHAT ]; then
     yum install -y python-setuptools
     yum install -y python-pip
  fi
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

function update_restart_kubelet()
{
  #check for manifests in kubelet config
  kubeappendoc=" --network-plugin=opencontrail"
  kubeappendpv=" --allow_privileged=true"
  kubeappendmf=" --config=/etc/kubernetes/manifests"
  if [ ! -f /etc/kubernetes/manifests ]; then
     mkdir -p /etc/kubernetes/manifests
  fi
  # Note: KUBELET_OPTS is used in Ubuntu
  #       DAEMON_ARGS is ised in AWS
  source /etc/default/kubelet
  if [ ! -z "$KUBELET_OPTS" ]; then
     kubecf=`echo $KUBELET_OPTS`
  elif [ ! -z "$DAEMON_ARGS" ]; then
     kubecf=`echo $DAEMON_ARGS`
  fi

  # kubelet runtime args are imp. Make sure it is up
  kubepid=$(ps -ef|grep kubelet |grep manifests | awk '{print $2}')
  if [ -z $kubepid ]; then
    service restart kubelet
  fi
  if [[ $kubepid != `pidof kubelet` ]]; then
      mkdir -p /etc/kubernetes/manifests
      kubecf="$kubecf $kubeappendmf"
  fi
  kubepid=$(ps -ef|grep kubelet |grep allow_privileged | awk '{print $2}')
  if [[ $kubepid != `pidof kubelet` ]]; then 
     kubecf="$kubecf $kubeappendpv"
  fi
  kubepid=$(ps -ef|grep kubelet |grep opencontrail | awk '{print $2}')
  if [[ $kubepid != `pidof kubelet` ]]; then
     kubecf="$kubecf $kubeappendoc"
  fi

  if [ ! -z "$KUBELET_OPTS" ]; then
    echo 'KUBELET_OPTS="'$kubecf'"' > /etc/default/kubelet
  elif [ ! -z "$DAEMON_ARGS" ]; then
    echo 'DAEMON_ARGS="'$kubecf'"' > /etc/default/kubelet
  fi
  service kubelet restart
}

function stop_kube_svcs()
{
   if [[ -n `pidof kube-proxy` ]]; then
      log_info_msg "Kube-proxy is running. Opencontrail does not use kube-proxy as it provides the function. Stoping it."
      `service kube-proxy stop`
      if [ "$OS_TYPE" == $UBUNTU ]; then
         `update-rc.d -f kube-proxy disable`
         `update-rc.d -f kube-proxy remove`
      else
         `chkconfig kube-proxy off`
      fi
   fi

   if [[ -n `pidof flanneld` ]]; then
      log_info_msg "flanneld is running. Opencontrail does not use flannel as it provides the function. Stoping it."
      service flanneld stop
      intf=$(ifconfig flannel | awk 'NR==1{print $1}')
      if [ $intf == "flannel0" ]; then
         `ifconfig $intf down`
         `ifdown $intf`
         if [ "$OS_TYPE" == $UBUNTU ]; then
            `update-rc.d -f flanneld disable`
            `update-rc.d -f flanneld remove`
         else
            `chkconfig flanneld off`
         fi
      fi
   fi
}

function update_vhost_pre_up()
{
  preup="/etc/network/if-pre-up.d"
  ifup_file="$preup/ifup-vhost"

  if [ "$OS_TYPE" == $REDHAT ]; then
     preup="/etc/sysconfig/network-scripts"
     ifup_file="$preup/ifup-vhost"
  fi

  if [ -f "$ifup_file" ]; then
    rm -f "$ifup_file"
  fi
  wget -P $preup https://raw.githubusercontent.com/Juniper/contrail-kubernetes/vrouter-manifest/scripts/opencontrail-install/ifup-vhost
  `chmod +x $preup/ifup-vhost`
}

function prereq_vrouter_agent()
{
  docpid=`pidof docker`
  if [ -z $docpid ]; then
   service docker restart
   docpid=`pidof docker`
  fi

  if  [ -z $docpid ]; then
    (exec /usr/bin/docker -d)&
  fi
}

function vrouter_agent_startup()
{
  etcc="/etc/contrail"
  vra_file="$etcc/contrail-vrouter-agent.conf"
  if [ ! -f $etcc ]; then
       mkdir -p $etcc
  fi

  if [ -f "$vra_file" ]; then
    rm -f "$vra_file"
  fi

  wget -P $etcc https://raw.githubusercontent.com/Juniper/contrail-controller/$ocver/src/vnsw/agent/contrail-vrouter-agent.conf
  def=$(ip route  | grep $OPENCONTRAIL_VROUTER_INTF | grep -o default)
  cidr=$(sipcalc $OPENCONTRAIL_VROUTER_INTF | grep "Network mask (bits)" | awk '{print $5}')
  if [ -z $cidr ]; then
    # check on vhost0 assuming its a rerun
    cidr=$(sipcalc $VHOST | grep "Network mask (bits)" | awk '{print $5}')
  fi
  if [ -z $cidr ]; then
    log_error_msg "Unable to get CIDR for networks on $OPENCONTRAIL_VROUTER_INTF and $VHOST. Please check interface and network and rerun"
    log_error_msg "Proceeding with CIDR unkown. Correct this issue by manually editing contrail-vrouter-agent.con for IP"
  fi
  vrac="$etcc/contrail-vrouter-agent.conf"
  via="via"
  ur="Usable range"
  if [ -f $vrac ]; then
      sed -i 's/log_file=/var/log/contrail/contrail-vrouter-agent.log/#log_file=/var/log/contrail/contrail-vrouter-agent.log/g' $vrac
      sed -i 's/# tunnel_type=/tunnel_type=MPLSoUDP/g' $vrac
      sed -i 's/# server=10.0.0.1 10.0.0.2/server='$OPENCONTRAIL_CONTROLLER_IP'/g' $vrac
      sed -i 's/# collectors=127.0.0.1:8086/collectors='$OPENCONTRAIL_CONTROLLER_IP':8086/g' $vrac
      sed -i 's/# type=kvm/type=docker/g' $vrac
      sed -i 's/# control_network_ip=/control_network_ip='$MINION_OVERLAY_NET_IP'/g' $vrac
      sed -i 's/# name=vhost0/name=vhost0/g' $vrac
      sed -i 's,# ip=10.1.1.1/24,ip='$MINION_OVERLAY_NET_IP/$cidr',g' $vrac
      if [ "$def" == "default" ]; then
         defgw=$(ip route | grep $OPENCONTRAIL_VROUTER_INTF | grep $def | awk 'NR==1{print $3}')
      else
         defgw=$(ip route | grep $OPENCONTRAIL_VROUTER_INTF | grep '$via' | awk 'NR==1{print $3}')
      fi
      if [ -z $defgw ]; then
         # assuming .1 is the gw for the range which is what kubernetes network provider 
         # assigns. If found different we need to change it
         defgw=$(sipcalc $OPENCONTRAIL_VROUTER_INTF | grep '$ur' | awk '{print $4}')
      fi
      if [ -z $defgw ]; then
         # check IP on VHOST
         vip=$(ip a | grep $VHOST | grep inet | awk -F/ '{print $1}' | awk '{print $2}')
         if [ $vip == $MINION_OVERLAY_NET_IP ]; then
            defgw=$(ip route | grep $VHOST | grep $via | awk 'NR==1{print $3}')
         fi
      fi
      sed -i 's,# gateway=10.1.1.254,gateway='$defgw',g' $vrac
      sed -i 's/# physical_interface=vnet0/physical_interface='$OPENCONTRAIL_VROUTER_INTF'/g' $vrac
      sed -i 's/compute_node_address = 10.204.216.28/#compute_node_address = /g' $vrac
  fi
  if [ ! -f /etc/kubernetes/manifests ]; then
     mkdir -p /etc/kubernetes/manifests
  fi
  vra_manifest="/etc/kubernetes/manifests/contrail-vrouter-agent.manifest"
  if [ -f "$vra_manifest" ]; then
     rm -f "$vra_manifest"
  fi
  wget -P /tmp https://raw.githubusercontent.com/Juniper/contrail-kubernetes/vrouter-manifest/cluster/contrail-vrouter-agent.manifest
  vragentfile=/tmp/contrail-vrouter-agent.manifest
  vrimg=$(cat $vragentfile | grep image | awk -F, '{print $1}' | awk '{print $2}')
  echo $vrimg | xargs -n1 sudo docker pull
  mv /tmp/contrail-vrouter-agent.manifest /etc/kubernetes/manifests  
}

function verify_vhost_setup()
{
  ifup $VHOST
  status=$(ping -c 1 -w 1 -W 1 -n $OPENCONTRAIL_CONTROLLER_IP | grep packet | awk '{print $6}' | cut -c1)
  if [ $status == 0 ]; then
    log_info_msg "Vrouter kernel module and network successfuly setup"
  else
    log_info_msg "Vrouter kernel module and network - Error"
  fi
}

function provision_vrouter()
{
  stderr="/tmp/stderr"
  host=`hostname -s`
  curl -X POST -H "Content-Type: application/json; charset=UTF-8" -d '{"virtual-router": {"parent_type": "global-system-config", "fq_name": ["default-global-system-config", "'$host'" ], "display_name": "'$host'", "virtual_router_ip_address": "'$MINION_OVERLAY_NET_IP'", "name": "'$host'"}}' http://$OPENCONTRAIL_CONTROLLER_IP:8082/virtual-routers 2> >( cat <() > $stderr)
  if [ -z $stderr ]; then
     log_info_msg "Provisioning of vrouter successful"
  else
     log_info_msg "Provisioning vrouter failed. Please check contrail-api and network to api server. It could also a duplicate entry"
  fi
}

function cleanup()
{
  if [ "$OS_TYPE" == $REDHAT ]; then
    yum remove -y git flex bison gcc gcc-c++ boost boost-devel scons libxml2-devel kernel-devel-`uname -r` sipcalc automake make wget
  elif [ "$OS_TYPE" == $UBUNTU ]; then
    apt-get remove -y git flex bison g++ gcc make libboost-all-dev scons libxml2-dev linux-headers-`uname -r` sipcalc automake make wget
  fi
  rm -rf ~/vrouter-build
  rm -rf /tmp/provision_vrouter.py
}

function verify_vrouter_agent()
{
  status=$(lsmod |grep vrouter | awk '{print $3}')
  if [ "$status" != "1" ]; then
    log_error_msg "Vrouter agent not launched successfuly. Please check contrail-vrouter-agent docker and vrouter kernel module"
    return
  fi
  vra_introspect_status=$(netstat -natp | grep 8085 | grep contrail | awk '{print $6}')
  vra_api_status=$(netstat -natp | grep 9090 | grep contrail | awk '{print $6}')
  vra_thrift_status=$(netstat -natp | grep 9091 | grep contrail | awk '{print $6}')
  if [[ $vra_introspect_status && $vra_api_status && $vra_thrift_status ]]; then
     log_info_msg "Vrouter agent is up and running"
  else
     log_error_msg "Issue with vrouter agent container. Please check vrouter agent configuration and the contrainer"
  fi

  vra_ctrl_status=$(netstat -natp | grep 5269 | grep contrail | awk '{print $6}')
  vra_coll_status=$(netstat -natp | grep 8086 | grep contrail | awk '{print $6}')
  vra_dns_status=$(netstat -natp | grep 53 | grep contrail | awk '{print $6}')
  if [[ $vra_ctrl_status && $vra_coll_status && $vra_dns_status ]]; then
      log_info_msg "Vrouter agent is successfully connected to contrail-control, contrail-collector and skyDNS"
  else
      log_error_msg "Vrouter agent is not connected to either contrail-control(port-5269), contrail-collector(port-8086) OR skyDNS(port-53). Please check services and connectivity"
  fi
}

function main()
{
   detect_os
   prep_to_build
   build_vrouter
   setup_vhost
   modprobe_vrouter
   setup_opencontrail_kubelet
   update_restart_kubelet
   stop_kube_svcs
   update_vhost_pre_up
   verify_vhost_setup
   prereq_vrouter_agent
   vrouter_agent_startup
   provision_vrouter
   cleanup
   verify_vrouter_agent
   log_info_msg "Provisioning of opencontrail-vrouter kernel and opencontrail-vrouter agent is done."
}

main
