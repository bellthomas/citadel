#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

[ ! -f "app" ] && make -C $DIR 
[ ! -f "app" ] && exit 1

$DIR/app declassify $1