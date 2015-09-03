#!/usr/bin/env bash

rm -rf manifests.hash
md5sum *.* | \grep -v $(basename $0) | awk '{print $2 " md5="$1}' > manifests.hash
