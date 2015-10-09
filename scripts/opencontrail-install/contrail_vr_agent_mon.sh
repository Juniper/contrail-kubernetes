#!/bin/bash
############################################################
# Opencontrail script to monitor agent container
# Author - Sanju Abraham -@asanju- OpenContrail-Kubernetes
###########################################################
docid=$(docker ps | grep vrouter | awk '{print $1}')
xmpp=$(netstat -natp |grep 5269 | awk '{print $6}')
img=$(docker images | grep vrouter | awk '{print $1}')
ver=$(docker images | grep vrouter | awk '{print $2}')
if [[ -n "$docid" ]] && [ "$xmpp" != "ESTABLISHED" ]; then
   docker restart $docid
   echo "Restarted contrail-vrouter-agent container"

else 
  docker run --privileged -d -P --name contrail_vrouter_agent --net="host" -t -i -e sysimage=/host -v /etc/contrail:/etc/contrail -v /var/log/contrail:/var/log/contrail $img:$ver /usr/bin/contrail-vrouter-agent 
   echo "Started contrail-vrouter-agent in docker"
fi
