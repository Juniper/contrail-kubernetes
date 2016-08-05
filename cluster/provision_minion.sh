#!/bin/bash
##############################################################
# opencontrail-kubernetes minion setup and provisioning script. 
# For more info, please refer to the following link
# https://github.com/Juniper/contrail-kubernetes
#
# Author - Sanju Abraham -@asanju- OpenContrail-Kubernetes
#
##############################################################
set -x

source /etc/contrail/opencontrail-rc

readonly PROGNAME=$(basename "$0")

runok="/etc/contrail/vrouter_prov_run.ok"
ocver=$OPENCONTRAIL_TAG
ockver=$OPENCONTRAIL_KUBERNETES_TAG
OPENCONTRAIL_PUBLIC_SUBNET="${OPENCONTRAIL_PUBLIC_SUBNET:-10.1.0.0/16}"
NETWORK_PROVIDER_GATEWAY_ON_MINION="${NETWORK_PROVIDER_GATEWAY_ON_MINION:-false}"
GCLOUD_NET_ADDR="${GCE_DEFAULT_IP_RANGE:-10.128.0.0/20}"

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

REDHAT="redhat"
UBUNTU="ubuntu"
VROUTER="vrouter"
VHOST="vhost0"

if [[ -z $ocver ]]; then
   ocver="R2.20"
fi

if [[ -z $ockver ]]; then
   ockver="master"
fi

hname=`hostname`

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

function generate_rc()
{
flag=false
rcfile="/etc/contrail/opencontrail-rc"
rcdir=`dirname "$rcfile"`
if [ ! -f "$rcdir" ]; then
    mkdir -p "$rcdir"
fi
if [[ -z $OPENCONTRAIL_CONTROLLER_IP ]]; then
    kube_api_port=$(cat /etc/default/kubelet | grep -o 'api-servers=[^;]*' | awk -F// '{print $2}' | awk '{print $1}')
    kube_api_server=$(echo $kube_api_port| awk -F':' '{print $1}')

   # Try to resolve
   if [[ -n $kube_api_server ]]; then
       OPENCONTRAIL_CONTROLLER_IP=$(host $kube_api_server | grep address | awk '{print $4}')
   elif [ -z "$kube_api_server" ]; then
       OPENCONTRAIL_CONTROLLER_IP=`hostname -i`
   else
      log_error_msg "Unable to resolve to contrail controller which is deployed on Kubernetes master"
   fi
   echo "OPENCONTRAIL_CONTROLLER_IP=$OPENCONTRAIL_CONTROLLER_IP" >> $rcfile
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
}

function prep_to_install()
{
  if [ "$OS_TYPE" == $REDHAT ]; then
    yum update
    yum install -y  libxml2-devel python-lxml sipcalc wget ethtool bridge-utils curl libxml2-utils \
        host dnsutils tcpdump
  elif [ "$OS_TYPE" == $UBUNTU ]; then
    # in case of an interrupt during execution of apt-get
    apt-get update --fix-missing
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" --force-yes libxml2-dev python-lxml sipcalc wget ethtool bridge-utils \
    curl host libxml2-utils \
    dnsutils tcpdump
  fi
}

function isGceVM()
{
  if [ -f /var/run/google.onboot ]; then
   return 0
  else
   return 1
  fi
}

function getGceNetAddr()
{
  if [ -z "$GCLOUD_NET_ADDR" ]; then
     GCLOUD_NET_ADDR=$(gcloud compute networks list | grep default | awk '{print $2}')
  fi
  echo $GCLOUD_NET_ADDR
  return 1
}

function setup_vhost()
{
  phy_itf=$(ip a |grep $MINION_OVERLAY_NET_IP | awk '{print $7}')
  if [ "$phy_itf" == $VHOST ]; then
     log_info_msg "MINION_OVERLAY_NET_IP is already on $VHOST. No change required on the this interface"
     return
  fi
  mask=$(ifconfig $phy_itf | grep -i '\(netmask\|mask\)' | awk '{print $4}' | cut -d ":" -f 2)
  if isGceVM ; then
     log_info_msg "Getting network address and mask for GCE VM"
     naddr=$(getGceNetAddr)
     mask=$(sipcalc $naddr | grep "Network mask" | head -n 1 | awk '{print $4}')
  fi
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
     if [ "$phy_itf" != "$VHOST" ]; then
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
  else
     # Make room for vrouter memory blocks in debian env
     sync
     echo 3 > /proc/sys/vm/drop_caches
  fi

  if [ -f "$ifup_file" ]; then
    rm -f "$ifup_file"
  fi
  wget -P $preup https://raw.githubusercontent.com/Juniper/contrail-kubernetes/$ockver/scripts/opencontrail-install/ifup-vhost
  `chmod +x $preup/ifup-vhost`
}

function prereq_vrouter_agent()
{
  if [[ "$OS_TYPE" == $REDHAT ]]; then
     docon=$(rpm -qa | grep docker)
  elif [[ "$OS_TYPE" == $UBUNTU ]]; then
     docon=$(dpkg -l | grep docker)
  fi

  iF=$(dpkg -l |grep docker-engine | awk '{print $1}')

  if [ "$iF" == "iF" ] || [ "$iF" == "iFR" ]; then
     dpkg --remove --force-remove-reinstreq docker-engine
     apt-get remove --purge docker-engine -y
  fi
  docon=$(dpkg -l | grep docker)

  if [ -z "$docon" ]; then
     if [[ "$OS_TYPE" == $UBUNTU ]]; then
            apt-get update --fix-missing
            rm -rf /var/cache/docker-install/docker-engine*
            wget --directory-prefix=/var/cache/docker-install http://apt.dockerproject.org/repo/pool/main/d/docker-engine/docker-engine_1.11.2-0~wheezy_amd64.deb
            dpkg -i /var/cache/docker-install/docker-engine/docker-engine_1.11.2-0~wheezy_amd64.deb
     fi
  fi
}

function vr_agent_conf_image_pull()
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
      sed -i 's/# tunnel_type=/tunnel_type=MPLSoUDP/g' $vrac
      grep -q "server=$OPENCONTRAIL_CONTROLLER_IP" $vrac || sed -i "/CONTROL-NODE]/a server=$OPENCONTRAIL_CONTROLLER_IP" $vrac
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
      if isGceVM ; then
         grep -Fxq "subnet_hosts_resolvable=0" $vrac || sed -i '/# dhcp_relay_mode=/a subnet_hosts_resolvable=0' $vrac
      fi
      sed -i 's/# physical_interface=vnet0/physical_interface='$OPENCONTRAIL_VROUTER_INTF'/g' $vrac
      sed -i 's/compute_node_address = 10.204.216.28/# compute_node_address = /g' $vrac
  fi
  wget -P /tmp https://raw.githubusercontent.com/Juniper/contrail-kubernetes/$ockver/cluster/contrail-vrouter-agent.manifest
  vragentfile=/tmp/contrail-vrouter-agent.manifest
  vrimg=$(cat $vragentfile | grep image | awk -F, '{print $1}' | awk '{print $2}')
  docker_pull $vrimg
}

function docker_pull()
{
  img=$1
  (echo $img | xargs -n1 sudo docker pull) & pullpid=$!
  i=0
  while true
    do
      dvrimg=$(docker images | grep -ow vrouter-agent)
      if [ ! -z  "$dvrimg" ]; then
         break
      fi
      sleep 2
      ((i++))
      if [ $i -eq 12 ]; then
       if [ -d "/proc/${pullpid}" ]; then
          pkill -TERM -P $pullpid
          cnt=$(ps -ef|grep "docker pull" | grep vrouter-agent | wc -l)
          if [ $cnt -gt 1 ]; then
             log_info_msg "Restarting docker and retrying pull of $img"
             service docker restart
          fi
       fi
       # give time for docker to initialize
       sleep 60
       log_info_msg "pulling of $img was not successful in the initial attempt."
       (echo $img | xargs -n1 sudo docker pull) & pullpid=$!
       i=0
      fi
    done
}

function vr_agent_manifest_setup()
{
  if [ ! -f /etc/kubernetes/manifests ]; then
     mkdir -p /etc/kubernetes/manifests
  fi
  vra_manifest="/etc/kubernetes/manifests/contrail-vrouter-agent.manifest"
  if [ -f "$vra_manifest" ]; then
     rm -f "$vra_manifest"
  fi
  # Wait for the control node to be up
  # check 60 times in 5 min
  cc=''
  ifmapup=false
  while true
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
  mv /tmp/contrail-vrouter-agent.manifest /etc/kubernetes/manifests
}

function ifup_vhost()
{
  ifup $VHOST
  intf=$(vif --list | grep vhost | awk '{print $3}')
  if [[ "$intf" == $VHOST ]]; then
    log_info_msg "Vhost setup successfuly"
  else
    log_info_msg "Vhost setup - Error"
  fi
}

function routeconfig()
{
    if isGceVM ; then
       #configure point to point route
       #asssuming the container is debian or ubuntu
       naddr=$(getGceNetAddr)
       defgw=$(ip route | grep default | awk '{print $3}')
       route add -host $defgw $VHOST
       route del -net $naddr dev $VHOST
       hostroute="up route add -host $defgw dev $VHOST"
       netdel="up route del -net $naddr dev $VHOST"
       grep -q 'up route add -host' /etc/network/interfaces || sed -i "/gateway/a \\\t$hostroute\n\t$netdel" /etc/network/interfaces
    fi
}

function verify_vhost_setup()
{
  sleep 3
  status=$(ping -c 1 -w 1 -W 1 -n $OPENCONTRAIL_CONTROLLER_IP | grep packet | awk '{print $6}' | cut -c1)
  if [ "$status" == 0 ]; then
    log_info_msg "Vrouter kernel module and network successfuly setup"
  else
    log_info_msg "Vrouter kernel module and network - Error"
  fi
}

# vrouter registering to API server should be in the vrouter
# and not in the contrail control server.
function provision_vrouter()
{
  stderr="/tmp/stderr"
  host=`hostname -s`

  # check if contrail-api is up 60 times, for 5 mins
  vr=''
  for (( i=0; i<60; i++ ))
    do
     vr=$(curl -s http://$OPENCONTRAIL_CONTROLLER_IP:8082 | grep -ow "virtual-routers")
     if [ ! -z $vr ]; then
       break
     fi
     sleep 3
    done
  curl -s -X POST -H "Content-Type: application/json; charset=UTF-8" -d '{"virtual-router": {"parent_type": "global-system-config", "fq_name": ["default-global-system-config", "'$host'" ], "display_name": "'$host'", "virtual_router_ip_address": "'$MINION_OVERLAY_NET_IP'", "name": "'$host'"}}' http://$OPENCONTRAIL_CONTROLLER_IP:8082/virtual-routers 2> >( cat <() > $stderr)
  err=$(cat $stderr)
  if [ -z "$err" ]; then
     log_info_msg "Provisioning of vrouter successful"
  else
     log_error_msg "Error in provisioning vrouter $err"
     log_info_msg "Provisioning vrouter failed. Please check contrail-api and network to api server. It could also a duplicate entry"
  fi
}

function cleanup()
{
  if [ "$OS_TYPE" == $REDHAT ]; then
    yum remove -y libxml2-devel sipcalc python-setuptools python-pip
  elif [ "$OS_TYPE" == $UBUNTU ]; then
    apt-get remove -y libxml2-dev sipcalc python-setuptools python-pip
  fi
}

function verify_vrouter_agent()
{
  lstn="LISTEN"
  estb="ESTABLISHED"
  vrlstn=false
  vrestb=false
  kernmodstat=false
  while true
    do
       vra_introspect_status=$(netstat -natp | grep 8085 | grep contrail-vr | awk '{print $6}')
       vra_api_status=$(netstat -natp | grep 9090 | grep contrail-vr | awk '{print $6}')
       vra_thrift_status=$(netstat -natp | grep 9091 | grep contrail-vr | awk '{print $6}')
       vra_ctrl_status=$(netstat -natp | grep 5269 | grep contrail-vr | awk '{print $6}')
       vra_coll_status=$(netstat -natp | grep 8086 | grep contrail-vr | awk '{print $6}')
       if [ "$vra_introspect_status" == $lstn ] && [ "$vra_api_status" == $lstn ] && [ "$vra_thrift_status" == $lstn ]; then
          vrlstn=true
       fi
       if [ "$vra_ctrl_status" == $estb ] && [ "$vra_coll_status" == $estb ]; then
          vrestb=true
       fi
       status=$(lsmod |grep vrouter | awk '{print $3}')
       if [ "$status" == 1 ]; then
          kernmodstat=true
       fi
       if [ "$vrlstn" == true ] && [ "$vrestb" == true ] && [ "$kernmodstat" == true ]; then
          log_info_msg "contrail-vrouter-agent is up and running"
          break
       else
          id=$(docker ps |grep contrail-vrouter-agent | grep -v pause | awk '{print $1}')
          if [[ -n $id ]]; then
            log_info_msg "contrail-vrouter-agent container up. Wait for additional time for agent to establish connections"
          else
            log_info_msg "contrail-vrouter-agent container is not up. Wait for additional time"
          fi
          sleep 3
       fi
    done
}

# Discover and add containers to vrouter
function discover_docc_addto_vrouter() {
    vrouter_agent=$(cat /etc/kubernetes/manifests/contrail-vrouter-agent.manifest | grep metadata | awk '{print $2}' | tr -d '{}",' | awk -F: '{print $2}')
    KUBE_PLUGIN=/usr/libexec/kubernetes/kubelet-plugins/net/exec/opencontrail/opencontrail
    CONTAINERS=$(docker ps | grep -v "/pause" | grep -v contrail | grep -v $vrouter_agent | awk '{print $1}' | grep -v CONTAINER)

    for i in $CONTAINERS; do
        NAME=$(docker inspect -f '{{.Name}}' $i)
        ID=$(docker inspect -f '{{.Id}}' $i)
        PODNAME=$(echo $NAME | awk '//{split($0, arr, "_"); print arr[3]}')
        NAMESPACE=$(echo $NAME | awk '//{split($0, arr, "_"); print arr[4]}')
        $KUBE_PLUGIN setup $NAMESPACE $PODNAME $ID
    done
}

function provision_virtual_gateway
{
    if $PROVISION_CONTRAIL_VGW ; then
        vrac="/etc/contrail/contrail-vrouter-agent.conf"
        wget -q --directory-prefix=/etc/contrail https://raw.githubusercontent.com/Juniper/contrail-controller/R2.20/src/config/utils/provision_vgw_interface.py
       `sudo docker ps |\grep contrail-vrouter-agent | \grep -v pause | awk '{print "sudo docker exec -it " $1 " python /etc/contrail/provision_vgw_interface.py --oper create --interface vgw --subnets '$OPENCONTRAIL_PUBLIC_SUBNET' --routes 0.0.0.0/0 --vrf default-domain:default-project:Public:Public"}'`
        # Setup virtual-gateway
        sed -i 's/# routing_instance=default-domain:admin:public:public$/routing_instance=default-domain:default-project:Public:Public/g' $vrac
        sed -i 's/# interface=vgw$/interface=vgw/g' $vrac
        PUBLIC_IP=$(echo $OPENCONTRAIL_PUBLIC_SUBNET | cut -d '/' -f 1)
        PUBLIC_LEN=$(echo $OPENCONTRAIL_PUBLIC_SUBNET | cut -d '/' -f 2)
        vgwipblk="'$PUBLIC_IP'\/'$PUBLIC_LEN'"
        sed -i 's/# ip_blocks=1\.1\.1\.1\/24$/ip_blocks='$PUBLIC_IP'\/'$PUBLIC_LEN'/g' $vrac
        sed -i "/GATEWAY-0/a routes=0.0.0.0/0" $vrac
    fi
}

function persist_hostname()
{
   if [ ! -f /etc/hostname ]; then
     echo "$hname" > /etc/hostname
     hostname $hname
   fi
}

function rpf_disable()
{
 echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
 echo 0 > /proc/sys/net/ipv4/conf/$OPENCONTRAIL_VROUTER_INTF/rp_filter
 echo 0 > /proc/sys/net/ipv4/conf/$VHOST/rp_filter
 echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
 echo "net.ipv4.conf."$OPENCONTRAIL_VROUTER_INTF".rp_filter=0" >> /etc/sysctl.conf
 echo "net.ipv4.conf."$VHOST".rp_filter=0" >> /etc/sysctl.conf
}

function add_static_route()
{
  itf="/etc/network/interfaces"
  if isGceVM ; then
     # Assuming the the default kubernetes container used is debain based
     # works only for debian / ubuntu
     ocpubgw=$(sipcalc $OPENCONTRAIL_PUBLIC_SUBNET | grep "Usable range" | awk '{print $6}')
     ocpubgwname=$(echo $ocpubgw | sed 's/\./-/g')
     ocpubmask=$(sipcalc $OPENCONTRAIL_PUBLIC_SUBNET | grep "Network mask" | head -n 1 | awk '{print $4}')
     zone=$(gcloud compute instances list | grep minion -A 1 | awk '{print $2}')
     srt=$(gcloud compute routes list | grep -ow ip-$ocpubgwname)
     if [ ! -z "$srt" ]; then
         gcloud compute routes delete ip-$ocpubgwname <<< "y
y
y
"
     fi
     gcloud compute routes create ip-$ocpubgwname --next-hop-instance `hostname` --next-hop-instance-zone $zone --destination-range $OPENCONTRAIL_PUBLIC_SUBNET
     # create and configure vgw with static IP
     # vgw will act as the gateway for public subnet
     grep -q 'auto vgw' $itf || echo -e "\nauto vgw" >> $itf
     grep -q 'iface vgw inet static' $itf || echo "iface vgw inet static" >> $itf
     grep -q "address $ocpubgw" $itf || echo -e "    address $ocpubgw\n    netmask $ocpubmask" >> $itf
     /etc/init.d/networking restart
  fi
  # Since we have vgw plumbed by both gke and vrouter there will
  # 2 routes for the same prefix. It will not have any issue though.
  # just for keeping it clean, delete the duplicate route
  net=$(echo $OPENCONTRAIL_PUBLIC_SUBNET | cut -d "/" -f 1)
  dups=$(route -n | grep vgw | grep $net | wc -l)
  if [ $dups -gt 1 ]; then
    route delete -net $OPENCONTRAIL_PUBLIC_SUBNET dev vgw
  fi
}

function pmtu_discovery()
{
  # This is as per RFC4821
  echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf
  # making sure to persist it as sysctl has issues
  # in some cases
  echo 1 > /proc/sys/net/ipv4/tcp_mtu_probing
  sysctl -p
}

function checksum_offload()
{
  # This is to get disable checksum on the GCE VM running opencontrail
  ethtool --offload eth0 rx off tx off
  ethtool -K eth0 gso off
}

function main()
{
   persist_hostname
   pmtu_discovery
   detect_os
   prep_to_install
   generate_rc
   setup_vhost
   stop_kube_svcs
   update_vhost_pre_up
   prereq_vrouter_agent
   vr_agent_conf_image_pull
   ifup_vhost
   routeconfig
   verify_vhost_setup
   vr_agent_manifest_setup
   provision_vrouter
   verify_vrouter_agent
   discover_docc_addto_vrouter
   rpf_disable
   if [ "$NETWORK_PROVIDER_GATEWAY_ON_MINION" == true ]; then
      vrhost=$(curl -s http://$OPENCONTRAIL_CONTROLLER_IP:8082/virtual-routers | python -c 'import sys, json; print json.load(sys.stdin)["virtual-routers"][0]["fq_name"][1]')
      if [ "$vrhost" == `hostname` ]; then
         provision_virtual_gateway
         add_static_route
      fi
   fi
   checksum_offload
   cleanup
   log_info_msg "Provisioning of opencontrail-vrouter kernel and opencontrail-vrouter agent is done."
   touch "$runok"
}

main
