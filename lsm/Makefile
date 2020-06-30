obj-y := \
	src/citadel.o \
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
		 

# Set to ccflags-y to enable debug logging in dmesg.
ccflags-n += -DCITADELDEBUG

# Ensure that we have the requisite RSA keys.
$(obj)/src/crypto/rsa.o: $(obj)/includes/lsm_keys.h

clean:
	$(shell) rm -rf ./**/*.a ./**/*.o ./**/.*.o.d ./**/.*.cmd
	$(shell) rm -rf modules.order key* scripts/*.pem scripts/rsa.*

