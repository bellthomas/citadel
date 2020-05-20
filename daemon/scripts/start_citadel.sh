#!/bin/bash
source /opt/intel/sgxsdk/environment
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TIME=$(date +%s)

# Sort logs.
mkdir -p $DIR/logs
[ -f $DIR/logs/citadel.log ] && mv $DIR/logs/citadel.log $DIR/logs/citadel.$TIME
touch $DIR/logs/citadel.log

# $DIR/citadel $@ | tee $DIR/logs/citadel.log
$DIR/citadel $@ > $DIR/logs/citadel.log