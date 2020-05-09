#!/bin/bash
TS=$(date +%s)
LSM_DIR=$1
if [ -z "$LSM_DIR" ]; then
    echo "No path provided. Using script path."
    LSM_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd .. && pwd )"
    echo $LSM_DIR
fi
SCRIPT_DIR="$LSM_DIR/scripts"

# Generate two key pairs.
PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
openssl genrsa -des3 -passout pass:$PASSWORD -out $SCRIPT_DIR/lsm.pem 2048
openssl genrsa -des3 -passout pass:$PASSWORD -out $SCRIPT_DIR/enclave.pem 2048

# Convert to DER format and extract public and private components.
openssl rsa -passin pass:$PASSWORD -outform der -in $SCRIPT_DIR/lsm.pem -out $SCRIPT_DIR/lsm_key.priv
openssl rsa -passin pass:$PASSWORD -outform der -in $SCRIPT_DIR/lsm.pem -pubout -out $SCRIPT_DIR/lsm_key_padded.pub
dd bs=24 skip=1 if=$SCRIPT_DIR/lsm_key_padded.pub of=$SCRIPT_DIR/lsm_key.pub

openssl rsa -passin pass:$PASSWORD -outform der -in $SCRIPT_DIR/enclave.pem -out $SCRIPT_DIR/enclave_key.priv
openssl rsa -passin pass:$PASSWORD -outform der -in $SCRIPT_DIR/enclave.pem -pubout -out $SCRIPT_DIR/enclave_key_padded.pub
dd bs=24 skip=1 if=$SCRIPT_DIR/enclave_key_padded.pub of=$SCRIPT_DIR/enclave_key.pub

rm $SCRIPT_DIR/lsm.pem $SCRIPT_DIR/enclave.pem 
PASSWORD=""

# Write encoded keys out as transient C structs.
KEY_FILES="enclave_key.priv enclave_key.pub enclave_key_padded.pub lsm_key.priv lsm_key.pub lsm_key_padded.pub"
for key_file in $KEY_FILES; do 
    key_name=${key_file/./_}
    xxd -i $SCRIPT_DIR/$key_file > $SCRIPT_DIR/rsa.$key_name
    rm -f $SCRIPT_DIR/$key_file
    N=$(grep -oP "[a-z0-9_]+(?=(_len))" $SCRIPT_DIR/rsa.$key_name)
    sed -i "s/$N/$key_name/g" $SCRIPT_DIR/rsa.$key_name
    echo "" >> $SCRIPT_DIR/rsa.$key_name
done

echo "$LSM_DIR/includes/lsm_keys.h"
echo "$LSM_DIR/daemon/enclave_core/enclave_keys.h"

# Construct final header files.
KEY_HEADER="// Auto generated, $TS."
echo -e $KEY_HEADER > $LSM_DIR/includes/lsm_keys.h 
cat $SCRIPT_DIR/rsa.lsm_key_priv >> $LSM_DIR/includes/lsm_keys.h 
cat $SCRIPT_DIR/rsa.lsm_key_pub >> $LSM_DIR/includes/lsm_keys.h 
cat $SCRIPT_DIR/rsa.enclave_key_pub >> $LSM_DIR/includes/lsm_keys.h 

echo -e $KEY_HEADER > $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $SCRIPT_DIR/rsa.enclave_key_priv >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $SCRIPT_DIR/rsa.enclave_key_padded_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $SCRIPT_DIR/rsa.enclave_key_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $SCRIPT_DIR/rsa.lsm_key_padded_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $SCRIPT_DIR/rsa.lsm_key_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 

rm $SCRIPT_DIR/rsa.*

# For testing.
# cp $LSM_DIR/daemon/enclave_keys.h $LSM_DIR/enclave_keys.h 
