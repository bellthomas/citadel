
App_Name := app

SOURCEDIR := src
SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
OBJECTS := $(SOURCES:%.c=%.o)

LIBCITADEL_PATH := ../libcitadel

NNG_Include_Folder := /opt/playground/nng/include
NNG_Library_Folder := /opt/devel/libnng

C_Includes := -I$(LIBCITADEL_PATH)/include -I$(NNG_Include_Folder)
C_Flags := -L$(LIBCITADEL_PATH) -lcitadel -L$(NNG_Library_Folder) -lnng -pthread

all: %: $(OBJECTS)
	@$(CC) -o $(App_Name) $(OBJECTS) $(C_Includes) $(C_Flags)
	@echo "   GEN     $(App_Name)"

%.o: %.c
	@$(CC) -c -o $@ $< $(C_Includes) $(C_Flags)
	@echo "   CC      $@"

.PHONY: clean
clean:
	@rm -f *.o **/*.o $(App_Name)
