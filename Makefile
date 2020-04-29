obj-y := src/trm.o \
	 src/ticket_cache.o \
	 src/crypto-rsa.o \
	 src/crypto-aes.o \
	 src/common.o \
	 src/io.o \
	 src/enclave_communication.o

# CFLAGS_trm.o := -msse2 -msse -march=native -maes

$(obj)/src/trm.o: $(obj)/includes/lsm_keys.h

$(obj)/includes/lsm_keys.h:
	$(call cmd,prepare_rsa)
	
	
##$(MAKE) -C $(obj)/daemon

quiet_cmd_prepare_rsa = GEN     $@
cmd_prepare_rsa = $(obj)/scripts/prepare_rsa.sh $(obj) > $(obj)/scripts/prepare_rsa.log 2>&1

clean:
	$(shell) rm -rf *.a src/*.o *.d includes/lsm_keys.h modules.order key* *.pem rsa.* includes/enclave_keys.h
	$(MAKE) -C daemon clean

clean-files := lsm_keys.h
