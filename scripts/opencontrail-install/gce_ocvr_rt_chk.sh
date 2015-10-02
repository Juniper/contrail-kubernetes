#!/bin/bash
############################################################
# Opencontrail script to update route 
# in case of a subnet with GW configured
# in L3 only mode. 
# Author - Sanju Abraham -@asanju- OpenContrail-Kubernetes
###########################################################
source /etc/contrail/opencontrail-rc

vmac=$(ip link show vhost0 | grep link | awk '{print $2}')
defgw=$(ip route | grep default | awk '{print $3}')
gwmac=$(/usr/sbin/arp -a | grep $defgw | awk '{print $4}')
intf=$(ip link show |grep $vmac -B 1 | grep -i "eth\|bond" | awk '{print $2}' | cut -d: -f1 | head -1)
naddr=$(/usr/local/bin/gcloud compute networks list | grep default | awk '{print $2}')
prefix=$(echo $naddr | cut -d/ -f1)
len=$(echo $naddr | cut -d/ -f2)

rtdata32=$(/usr/bin/rt --dump 0 | grep $OPENCONTRAIL_CONTROLLER_IP/32 | awk '{print $5}' | head -1)
if [ "$rtdata32" == "-" ]; then
   rtdata32=$(rt --dump 0 |grep $OPENCONTRAIL_CONTROLLER_IP/32 | awk '{print $4}' | head -1)
fi
oc=$OPENCONTRAIL_CONTROLLER_IP
sub=$(echo ${oc%.*} ${oc##*.}  | awk '{print $1}').0
rtdata24=$(/usr/bin/rt --dump 0 | grep $sub | awk '{print $5}' | head -1)
if [ "$rtdata24" == "-" ]; then
    rtdata24=$(rt --dump 0 |grep $sub | awk '{print $4}' | head -1)
fi
if [ ! -z $rtdata32 ] && [ ! -z $rtdata24 ]; then
  if [ "$rtdata32" != 1000 ] || [ "$rtdata24" != 1000 ]; then
     nhid=$(/usr/bin/rt --dump 0 | grep $OPENCONTRAIL_CONTROLLER_IP | awk '{print $5}' | head -1)
     if [ "$nhid" == "-" ]; then
        nhid=$(/usr/bin/rt --dump 0 | grep $OPENCONTRAIL_CONTROLLER_IP | awk '{print $4}' | head -1)
     fi
     /usr/bin/nh --delete $nhid
     /usr/bin/nh --create 1000 --type 2 --smac $vmac --dmac $gwmac --oif $intf
     while true
      do
        nhid=$(/usr/bin/rt --dump 0 | grep $OPENCONTRAIL_CONTROLLER_IP | awk '{print $5}' | head -1)
        if [ "$nhid" == "-" ]; then
           nhid=$(/usr/bin/rt --dump 0 | grep $OPENCONTRAIL_CONTROLLER_IP | awk '{print $4}' | head -1)
        fi
        rtdata32=$(/usr/bin/rt --dump 0 | grep $OPENCONTRAIL_CONTROLLER_IP/32 | awk '{print $5}' | head -1)
        if [ "$rtdata32" == "-" ]; then
           rtdata32=$(rt --dump 0 |grep $OPENCONTRAIL_CONTROLLER_IP/32 | awk '{print $4}' | head -1)
        fi
        if [ "$rtdata32" != 1000 ]; then
           err=$(/usr/bin/rt -d -f AF_INET -r $len -p $OPENCONTRAIL_CONTROLLER_IP -l 32 -n $nhid -v 0 | grep -ow Error)
           if [ "$err" == Error ]; then
             sleep 3
             continue
           else
             break
           fi
        fi
      done
     /usr/bin/rt -c -f AF_INET -n 1000 -p $prefix -l $len -v 0
  fi
fi

