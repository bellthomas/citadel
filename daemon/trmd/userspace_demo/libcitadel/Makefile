

SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJECTS := $(SOURCES:%.c=%.o)

NNG_Include_Folder := /opt/playground/nng/include
NNG_Library_Folder := /opt/devel/libnng

C_Includes := -I$(NNG_Include_Folder)
C_Flags := -L$(NNG_Library_Folder) -lnng -pthread
# -Wl,--no-whole-archive

all: libcitadel.a

# install: libcitadel.a
# 	@sudo cp libcitadel.so /usr/local/lib


libcitadel.a: %: $(OBJECTS)	
	@$(AR) rcs $@ $(OBJECTS)
	@echo "   AR      libcitadel.a"


#	@$(CC) -shared -o $@ $(OBJECTS) $(C_Includes) $(C_Flags) 

# @$(AR) rcs $@ $(OBJECTS)
# @cp $(NNG_Library_Folder)/libnng.a $@
# $(LIBNNG_FOLDER):
# 	@mkdir -p $(LIBNNG_FOLDER) && cd $(LIBNNG_FOLDER) && $(AR) x $(NNG_Library_Folder)/libnng.a
# 	@echo "   GEN     libnng"

%.o: %.c
	@$(CC) -c -o $@ $< $(C_Includes) $(C_Flags)
	@echo "   CC      $@"

.PHONY: clean
clean:
	@rm -rf *.o **/*.o *.a $(LIBNNG_FOLDER)