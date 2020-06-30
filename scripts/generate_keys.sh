#!/bin/bash
TS=$(date +%s)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
OUTPUT_DIR="$DIR/keys"
[ -d "$OUTPUT_DIR" ] && rm -rf $OUTPUT_DIR
mkdir -p $OUTPUT_DIR

# Generate two key pairs.
PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
openssl genrsa -des3 -passout pass:$PASSWORD -out $OUTPUT_DIR/lsm.pem 2048
openssl genrsa -des3 -passout pass:$PASSWORD -out $OUTPUT_DIR/enclave.pem 2048

# Convert to DER format and extract public and private components.
openssl rsa -passin pass:$PASSWORD -outform der -in $OUTPUT_DIR/lsm.pem -out $OUTPUT_DIR/lsm_key.priv
openssl rsa -passin pass:$PASSWORD -outform der -in $OUTPUT_DIR/lsm.pem -pubout -out $OUTPUT_DIR/lsm_key_padded.pub
dd bs=24 skip=1 if=$OUTPUT_DIR/lsm_key_padded.pub of=$OUTPUT_DIR/lsm_key.pub

openssl rsa -passin pass:$PASSWORD -outform der -in $OUTPUT_DIR/enclave.pem -out $OUTPUT_DIR/enclave_key.priv
openssl rsa -passin pass:$PASSWORD -outform der -in $OUTPUT_DIR/enclave.pem -pubout -out $OUTPUT_DIR/enclave_key_padded.pub
dd bs=24 skip=1 if=$OUTPUT_DIR/enclave_key_padded.pub of=$OUTPUT_DIR/enclave_key.pub

rm $OUTPUT_DIR/lsm.pem $OUTPUT_DIR/enclave.pem
PASSWORD=""

# Write encoded keys out as transient C structs.
KEY_FILES="enclave_key.priv enclave_key.pub enclave_key_padded.pub lsm_key.priv lsm_key.pub lsm_key_padded.pub enclave_keys.sealed"

# Assemble enclave blob for sealing.
cat $OUTPUT_DIR/enclave_key.priv > $OUTPUT_DIR/enclave_keys
cat $OUTPUT_DIR/enclave_key_padded.pub >> $OUTPUT_DIR/enclave_keys
cat $OUTPUT_DIR/enclave_key.pub >> $OUTPUT_DIR/enclave_keys
cat $OUTPUT_DIR/lsm_key_padded.pub >> $OUTPUT_DIR/enclave_keys
cat $OUTPUT_DIR/lsm_key.pub >> $OUTPUT_DIR/enclave_keys

# Invoke preparatory enclave.
private_keylen=$(stat -c%s "$OUTPUT_DIR/enclave_key.priv")
echo $private_keylen
make -C $DIR/preparatory_enclave SGX_SDK=$1
$DIR/preparatory_enclave/build/app $DIR/preparatory_enclave/build/libpreparation.signed.so $OUTPUT_DIR/enclave_keys $private_keylen

for key_file in $KEY_FILES; do
    key_name=${key_file/./_}
    xxd -i $OUTPUT_DIR/$key_file > $OUTPUT_DIR/rsa.$key_name
    # rm -f $OUTPUT_DIR/$key_file
    N=$(grep -oP "[a-z0-9_]+(?=(_len))" $OUTPUT_DIR/rsa.$key_name)
    sed -i "s/$N/$key_name/g" $OUTPUT_DIR/rsa.$key_name
    echo "" >> $OUTPUT_DIR/rsa.$key_name
done

# echo "$LSM_DIR/includes/lsm_keys.h"
# echo "$LSM_DIR/daemon/enclave_core/enclave_keys.h"

# Construct final header files.
KEY_HEADER="// Auto generated, $TS."
echo -e $KEY_HEADER > $OUTPUT_DIR/lsm_keys.h
cat $OUTPUT_DIR/rsa.lsm_key_priv >> $OUTPUT_DIR/lsm_keys.h
cat $OUTPUT_DIR/rsa.lsm_key_pub >> $OUTPUT_DIR/lsm_keys.h
cat $OUTPUT_DIR/rsa.enclave_key_pub >> $OUTPUT_DIR/lsm_keys.h

#echo -e $KEY_HEADER > $OUTPUT_DIR/enclave_keys.h
#cat $OUTPUT_DIR/rsa.enclave_key_priv >> $OUTPUT_DIR/enclave_keys.h
#cat $OUTPUT_DIR/rsa.enclave_key_padded_pub >> $OUTPUT_DIR/enclave_keys.h
#cat $OUTPUT_DIR/rsa.enclave_key_pub >> $OUTPUT_DIR/enclave_keys.h
#cat $OUTPUT_DIR/rsa.lsm_key_padded_pub >> $OUTPUT_DIR/enclave_keys.h
#cat $OUTPUT_DIR/rsa.lsm_key_pub >> $OUTPUT_DIR/enclave_keys.h

echo -e $KEY_HEADER > $OUTPUT_DIR/sealed_enclave_keys.h
cat $OUTPUT_DIR/rsa.enclave_keys_sealed >> $OUTPUT_DIR/sealed_enclave_keys.h



# rm $OUTPUT_DIR/rsa.*
