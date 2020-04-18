#!/bin/bash
TS=$(date +%s)
LSM_DIR=$1
if [ -z "$var" ]; then
    echo "No path provided. Using script path."
    LSM_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
fi

# Generate two key pairs.
PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
openssl genrsa -des3 -passout pass:$PASSWORD -out $LSM_DIR/lsm.pem 2048
openssl genrsa -des3 -passout pass:$PASSWORD -out $LSM_DIR/enclave.pem 2048

# Convert to DER format and extract public and private components.
openssl rsa -passin pass:$PASSWORD -outform der -in $LSM_DIR/lsm.pem -out $LSM_DIR/lsm_key.priv
openssl rsa -passin pass:$PASSWORD -outform der -in $LSM_DIR/lsm.pem -pubout -out $LSM_DIR/lsm_key_padded.pub
dd bs=24 skip=1 if=$LSM_DIR/lsm_key_padded.pub of=$LSM_DIR/lsm_key.pub

openssl rsa -passin pass:$PASSWORD -outform der -in $LSM_DIR/enclave.pem -out $LSM_DIR/enclave_key.priv
openssl rsa -passin pass:$PASSWORD -outform der -in $LSM_DIR/enclave.pem -pubout -out $LSM_DIR/enclave_key_padded.pub
dd bs=24 skip=1 if=$LSM_DIR/enclave_key_padded.pub of=$LSM_DIR/enclave_key.pub

rm $LSM_DIR/lsm.pem $LSM_DIR/enclave.pem 
PASSWORD=""

# Write encoded keys out as transient C structs.
KEY_FILES="enclave_key.priv enclave_key.pub enclave_key_padded.pub lsm_key.priv lsm_key.pub lsm_key_padded.pub"
for key_file in $KEY_FILES; do 
    key_name=${key_file/./_}
    xxd -i $LSM_DIR/$key_file > $LSM_DIR/rsa.$key_name
    rm -f $LSM_DIR/$key_file
    N=$(grep -oP "_[a-z0-9_]*(?=(_len))" $LSM_DIR/rsa.$key_name)
    sed -i "s/$N/$key_name/g" $LSM_DIR/rsa.$key_name
    echo "" >> $LSM_DIR/rsa.$key_name
done

# Construct final header files.
KEY_HEADER='// Auto generated.'
echo -e $KEY_HEADER > $LSM_DIR/lsm_keys.h 
cat $LSM_DIR/rsa.lsm_key_priv >> $LSM_DIR/lsm_keys.h 
cat $LSM_DIR/rsa.lsm_key_pub >> $LSM_DIR/lsm_keys.h 
cat $LSM_DIR/rsa.enclave_key_pub >> $LSM_DIR/lsm_keys.h 

echo -e $KEY_HEADER > $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $LSM_DIR/rsa.enclave_key_priv >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $LSM_DIR/rsa.enclave_key_padded_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $LSM_DIR/rsa.enclave_key_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $LSM_DIR/rsa.lsm_key_padded_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 
cat $LSM_DIR/rsa.lsm_key_pub >> $LSM_DIR/daemon/enclave_core/enclave_keys.h 

rm $LSM_DIR/rsa.*

# For testing.
# cp $LSM_DIR/daemon/enclave_keys.h $LSM_DIR/enclave_keys.h 