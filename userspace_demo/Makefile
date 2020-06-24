
App_Name := app

SOURCEDIR := src
SOURCES := $(shell find $(SOURCEDIR) -name '*.cpp')
OBJECTS := $(SOURCES:%.cpp=%.o)

LIBCITADEL_PATH := ../libcitadel

C_Includes := -I$(LIBCITADEL_PATH)/include
C_Flags :=  -lcitadel -L$(LIBCITADEL_PATH) -pthread

all: %: $(OBJECTS)
	@$(CXX) -o $(App_Name) $(OBJECTS) $(C_Includes) $(C_Flags) 
	@echo "   GEN     $(App_Name)"

%.o: %.cpp
	@$(CXX) -c -o $@ $< $(C_Includes) $(C_Flags)
	@echo "   CXX     $@"

.PHONY: clean
clean:
	@rm -f *.o **/*.o $(App_Name)
