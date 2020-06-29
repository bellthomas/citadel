obj-y := src/citadel.o \
         src/common.o \
         src/crypto/rsa.o \
         src/crypto/aes.o \
         src/communication/file_io.o \
         src/communication/payload_io.o \
	 src/lsm_functions/inode.o \
	 src/lsm_functions/file.o \
	 src/lsm_functions/task.o \
	 src/lsm_functions/socket.o \
	 src/lsm_functions/ipc.o \
	 src/ticketing/ticket_cache.o \
	 src/ticketing/shm_tracking.o
		 


# CFLAGS_trm.o := -msse2 -msse -march=native -maes

# Ensure that we generate the 2048-bit RSA keys.
$(obj)/src/crypto/rsa.o: $(obj)/includes/lsm_keys.h


clean:
	$(shell) rm -rf ./**/*.a ./**/*.o ./**/.*.o.d ./**/.*.cmd
	$(shell) rm -rf includes/lsm_keys.h modules.order key* scripts/*.pem scripts/rsa.*

clean-files := includes/lsm_keys.h
