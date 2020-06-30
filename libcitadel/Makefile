
SOURCEDIR := src
SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJECTS := $(SOURCES:%.c=%.o)

override CFLAGS += -pthread -D_GNU_SOURCE -fPIC

all: libcitadel.a

libcitadel.a: %: $(OBJECTS)	
	@$(AR) rcs $@ $(OBJECTS)
	@echo "   AR      libcitadel.a"

%.o: %.c
	@$(CC) -c -o $@ $< $(C_Includes) $(CFLAGS)
	@echo "   CC      $@"

.PHONY: clean
clean:
	@rm -rf *.o **/*.o *.a
