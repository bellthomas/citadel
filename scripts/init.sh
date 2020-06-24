#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PARENT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"
KERNEL_ARCHIVE_URL="https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.6.2.tar.xz"
KERNEL_ARCHIVE="${KERNEL_ARCHIVE_URL##*/}"
KERNEL_TAR_ARCHIVE=${KERNEL_ARCHIVE%".xz"}
KERNEL_VERSION=${KERNEL_ARCHIVE%".tar.xz"}
CITADEL_KERNEL_FOLDER="$KERNEL_VERSION.citadel"

# Header.
printf "\n//  Citadel Build Script  //\n\n"

# Get the desired install location.
echo "Install Directory [$PARENT/kernel]"
read -e -p "-> " KERNEL_SOURCE_PATH
KERNEL_SOURCE_PATH=${KERNEL_SOURCE_PATH:-"$PARENT/kernel"}

printf "\nInstalling to $KERNEL_SOURCE_PATH...\n"
[ ! -d "/path/to/dir" ] && mkdir -p $KERNEL_SOURCE_PATH
cd $KERNEL_SOURCE_PATH

# Download kernel source.
[ -d "$CITADEL_KERNEL_FOLDER" ] && rm -rf $CITADEL_KERNEL_FOLDER

if [ ! -f "$KERNEL_TAR_ARCHIVE" ]; then
    wget $KERNEL_ARCHIVE_URL
    xz -d -v $KERNEL_ARCHIVE
fi

tar xf ${KERNEL_ARCHIVE%".xz"}
mv $KERNEL_VERSION $CITADEL_KERNEL_FOLDER

# Move Citadel source.
CITADEL_LSM_PATH="$KERNEL_SOURCE_PATH/$CITADEL_KERNEL_FOLDER/security/citadel"
mkdir -p $CITADEL_LSM_PATH
cp -r $PARENT/lsm/* $CITADEL_LSM_PATH

mv $CITADEL_LSM_PATH/kernel.config "$KERNEL_SOURCE_PATH/$CITADEL_KERNEL_FOLDER/.config"
mv $CITADEL_LSM_PATH/security.Kconfig "$KERNEL_SOURCE_PATH/$CITADEL_KERNEL_FOLDER/security/Kconfig"

# Generate keys.
$DIR/generate_keys.sh
cp $DIR/keys/lsm_keys.h "$CITADEL_LSM_PATH/includes"

cp $DIR/keys/enclave_keys.h $PARENT/daemon/enclave_core/

rm -rf $DIR/keys
cd $DIR
