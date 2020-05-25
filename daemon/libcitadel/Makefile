
SOURCEDIR := src
SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJECTS := $(SOURCES:%.c=%.o)

NNG_Include_Folder := /opt/playground/nng/include
NNG_Library_Folder := /opt/devel/libnng

C_Includes := -I$(NNG_Include_Folder)
C_Flags := -L$(NNG_Library_Folder) -lnng -pthread -D_GNU_SOURCE
# -Wl,--no-whole-archive

all: libcitadel.a

libcitadel.a: %: $(OBJECTS)	
	@$(AR) rcs $@ $(OBJECTS)
	@echo "   AR      libcitadel.a"

%.o: %.c
	@$(CC) -c -o $@ $< $(C_Includes) $(C_Flags)
	@echo "   CC      $@"

.PHONY: clean
clean:
	@rm -rf *.o **/*.o *.a $(LIBNNG_FOLDER)