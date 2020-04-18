obj-y := trm.o \
	ticket_cache.o \
	crypto-rsa.o \
	crypto-aes.o \
	common.o

# CFLAGS_trm.o := -msse2 -msse -march=native -maes

$(obj)/trm.o: $(obj)/lsm_keys.h

$(obj)/lsm_keys.h:
	$(call cmd,prepare_rsa)
	
	
##$(MAKE) -C $(obj)/daemon

quiet_cmd_prepare_rsa = GEN     $@
cmd_prepare_rsa = $(obj)/prepare_rsa.sh $(obj) > /dev/null

clean:
	$(shell) rm -rf *.a *.o *.d lsm_keys.h modules.order key* *.pem rsa.* enclave_keys.h
	$(MAKE) -C daemon clean

clean-files := lsm_keys.h
