
App_Name := app

SOURCEDIR := src
SOURCES := $(shell find $(SOURCEDIR) -name '*.cpp')
OBJECTS := $(SOURCES:%.cpp=%.o)

LIBCITADEL_PATH := ../libcitadel

NNG_Include_Folder := /opt/playground/nng/include
NNG_Library_Folder := /opt/devel/libnng

C_Includes := -I$(LIBCITADEL_PATH)/include -I$(NNG_Include_Folder)
C_Flags :=  -lcitadel -L$(LIBCITADEL_PATH) -lnng -L$(NNG_Library_Folder) -pthread

all: %: $(OBJECTS)
	@$(CXX) -o $(App_Name) $(OBJECTS) $(C_Includes) $(C_Flags) 
	@echo "   GEN     $(App_Name)"

%.o: %.cpp
	@$(CXX) -c -o $@ $< $(C_Includes) $(C_Flags)
	@echo "   CXX     $@"

.PHONY: clean
clean:
	@rm -f *.o **/*.o $(App_Name)
