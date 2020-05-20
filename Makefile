obj-y := src/citadel.o \
         src/common.o \
         src/crypto/rsa.o \
         src/crypto/aes.o \
         src/communication/file_io.o \
         src/communication/payload_io.o \
		 src/lsm_functions/inode.o \
		 src/lsm_functions/file.o \
		 src/lsm_functions/task.o \
		 src/ticketing/ticket_cache.o
		 


# CFLAGS_trm.o := -msse2 -msse -march=native -maes

# Ensure that we generate the 2048-bit RSA keys.
$(obj)/src/crypto/rsa.o: $(obj)/includes/lsm_keys.h
$(obj)/includes/lsm_keys.h:
	$(call cmd,prepare_rsa)

quiet_cmd_prepare_rsa = GEN     $@
cmd_prepare_rsa = $(obj)/scripts/prepare_rsa.sh $(obj) > $(obj)/scripts/prepare_rsa.log 2>&1
# end.

clean:
	$(shell) rm -rf ./**/*.a src/**/*.o ./**/.*.o.d ./**/.*.cmd
	$(shell) rm -rf includes/lsm_keys.h modules.order key* scripts/*.pem scripts/rsa.* includes/enclave_keys.h
	$(MAKE) -C daemon clean

clean-files := includes/lsm_keys.h
