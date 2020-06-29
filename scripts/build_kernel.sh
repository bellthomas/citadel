#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PARENT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"

# Get the desired install location.
[ -f "$DIR/.kernel_path" ] && old_dir=$(cat "$DIR/.kernel_path") 
old_dir=${old_dir:-"$PARENT/kernel"}

echo "Install Directory [$old_dir]"
read -e -p "-> " KERNEL_SOURCE_PATH
KERNEL_SOURCE_PATH=${KERNEL_SOURCE_PATH:-"$old_dir"}
echo ""

make -C $KERNEL_SOURCE_PATH -j $(nproc)
printf "\nInstalling kernel modules... "
sudo make -C $KERNEL_SOURCE_PATH modules_install -j $(nproc) > /dev/null
printf "done.\n"
sudo make -C $KERNEL_SOURCE_PATH install -j $(nproc)