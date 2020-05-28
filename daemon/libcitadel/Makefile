
SOURCEDIR := src
SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJECTS := $(SOURCES:%.c=%.o)

C_Flags := -pthread -D_GNU_SOURCE

all: libcitadel.a

libcitadel.a: %: $(OBJECTS)	
	@$(AR) rcs $@ $(OBJECTS)
	@echo "   AR      libcitadel.a"

%.o: %.c
	@$(CC) -c -o $@ $< $(C_Includes) $(C_Flags)
	@echo "   CC      $@"

.PHONY: clean
clean:
	@rm -rf *.o **/*.o *.a