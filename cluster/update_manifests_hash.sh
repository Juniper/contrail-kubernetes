#!/usr/bin/env bash

md5sum *.manifest* | awk '{print $2 " md5="$1}' > manifests.hash
