#!/usr/bin/env bash

rm -rf manifests.hash
if [ -f /etc/issue ]; then
    md5sum *.* | \grep -v $(basename $0) | awk '{print $2 " md5="$1}' > manifests.hash
else # macos
    md5sum *.* | \grep -v $(basename $0) | awk '{print $2 " md5="$NF}' > /tmp/manifests.hash
    sed 's/(//' /tmp/manifests.hash > manifests.hash
    mv manifests.hash /tmp
    sed 's/)//' /tmp/manifests.hash > manifests.hash
    rm -rf /tmp/manifests.hash
fi
