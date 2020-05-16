
######## SGX SDK Settings ########

CWD := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
Build_Folder := build
Enclave_Impls := basic uflume
LibTomCrypt_Folder := $(CWD)/enclave_core/crypto/ltc
Install_Folder := /opt/citadel
Scripts_Folder := scripts
NNG_Include_Folder := /opt/playground/nng/include
NNG_Library_Folder := /opt/devel/libnng



ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
		SGX_COMMON_CFLAGS += -O0 -g
else
		SGX_COMMON_CFLAGS += -O2
endif




######## App Settings ########

App_Folder := citadel.d
App_Name := $(Build_Folder)/app

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := $(App_Folder)/app.cpp \
				 $(App_Folder)/sgx_utils/sgx_utils.cpp \
				 $(App_Folder)/lsm_io.cpp \
				 $(App_Folder)/socket.cpp 

App_Include_Paths := -I$(App_Folder) -I$(SGX_SDK)/include -I$(NNG_Include_Folder)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) 

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
		App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
		App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
		App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11 -I/opt/playground/nng/include
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) \
                  -Wl,--whole-archive  -lsgx_uswitchless -Wl,--no-whole-archive \
                  -l$(Urts_Library_Name) -lpthread -L/opt/devel/libnng -lnng -pthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)


######## Enclave Settings ########

Enclave_Folder := enclave_core
Enclave_Name := shouldnt be here
# Enclave_Names := $(Build_Folder)/enclave.so
Signed_Enclave_Name :=  shouldnt be here 2
Enclave_Config_File := $(Enclave_Folder)/Enclave.config.xml

ASM_Folder := asm_implementations
# Enclave_Impls := $(sort $(dir $(wildcard $(ASM_Folder)/*/)))
# SUFIX=$(addprefix bin/,$(notdir $(SOURCES:.c=.o)))

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(Enclave_Folder)/Enclave.cpp \
					 $(Enclave_Folder)/Sealing/Sealing.cpp \
					 $(Enclave_Folder)/asm/interface.cpp \
					 $(Enclave_Folder)/lsm_communication.cpp \
					 $(Enclave_Folder)/userspace_io.cpp \
			         $(Enclave_Folder)/crypto/rsa_encrypt.cpp \
			         $(Enclave_Folder)/crypto/rsa_decrypt.cpp \
			         $(Enclave_Folder)/crypto/aes.cpp

Enclave_Include_Paths := -I$(Enclave_Folder) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(LibTomCrypt_Folder)/src/headers -I/opt/devel/sgx-gmp

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_tswitchless -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -L$(LibTomCrypt_Folder) -ltomcrypt -L/opt/devel/sgx-gmp -lsgx_tgmp -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	# -Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)


ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) enclave install-app
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) enclave install-app libcitadel/libcitadel.a userspace_demo/app
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
	@sudo /opt/sgxrun /opt/citadel/citadel /opt/citadel/citadel.basic.signed.so
endif

######## App Objects ########

$(App_Folder)/Enclave_u.c: $(SGX_EDGER8R) $(Enclave_Folder)/Enclave.edl
	@cd $(App_Folder) && $(SGX_EDGER8R) --untrusted ../$(Enclave_Folder)/Enclave.edl --search-path ../$(Enclave_Folder) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(App_Folder)/Enclave_u.o: $(App_Folder)/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Folder)/%.o: $(App_Folder)/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(App_Folder)/Enclave_u.o $(App_Cpp_Objects)
	@[ -d $(Build_Folder) ] || mkdir $(Build_Folder)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########


$(Enclave_Folder)/Enclave_t.c: $(SGX_EDGER8R) $(Enclave_Folder)/Enclave.edl
	@cd $(Enclave_Folder) && $(SGX_EDGER8R) --trusted ../$(Enclave_Folder)/Enclave.edl --search-path ../$(Enclave_Folder) --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

$(Enclave_Folder)/Enclave_t.o: $(Enclave_Folder)/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Folder)/%.o: $(Enclave_Folder)/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"


#####

.PHONY: clean-enclave
clean-enclave:
	@rm -rf $(Enclave_Cpp_Objects) $(Enclave_Folder)/Enclave_t.* $(Enclave_Folder)/asm


citadel-%: clean-enclave 
	@mkdir -p $(Enclave_Folder)/asm
	@cp $(ASM_Folder)/$*/*.cpp $(Enclave_Folder)/asm
	@cp $(ASM_Folder)/$*/*.h $(Enclave_Folder)/asm


$(Build_Folder)/citadel.%.so: $(Enclave_Folder)/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $(Enclave_Folder)/Enclave_t.o $(Enclave_Cpp_Objects) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"


$(Build_Folder)/citadel.%.signed.so: $(Build_Folder)/citadel.%.so
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Folder)/Enclave_private.pem -enclave $(Build_Folder)/citadel.$*.so -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"


enclave-basic: citadel-basic $(Build_Folder)/citadel.basic.signed.so clean-enclave
enclave-uflume: citadel-uflume $(Build_Folder)/citadel.uflume.signed.so clean-enclave

enclave: enclave-basic

.PHONY: install-daemon install-app install
install-daemon:
	@sudo cp $(Scripts_Folder)/citadel.service /etc/systemd/system/
	@sudo systemctl enable citadel

install-app:
	@mkdir -p $(Install_Folder)
	@rm -rf $(Install_Folder)/*
	@cp -r $(Build_Folder)/* $(Install_Folder)/
	@mv $(Install_Folder)/app $(Install_Folder)/citadel
	@cp $(Scripts_Folder)/start_citadel.sh $(Install_Folder)/
	@sudo chmod +x $(Install_Folder)/start_citadel.sh

install: install-app install-daemon
	


.PHONY: clean enclave enclave-uflume libcitadel userspace_demo
clean: 
	@rm -rf $(App_Name) $(App_Cpp_Objects) $(App_Folder)/Enclave_u.* $(Enclave_Cpp_Objects) $(Enclave_Folder)/Enclave_t.* $(Enclave_Folder)/asm/*
	@rm -rf $(Build_Folder)/*
	@$(MAKE) --no-print-directory -C libcitadel clean
	@$(MAKE) --no-print-directory -C userspace_demo clean

libcitadel/libcitadel.a:
	@echo "\n/libcitadel"
	@$(MAKE) --no-print-directory -C libcitadel clean
	@$(MAKE) --no-print-directory -C libcitadel

userspace_demo/app:
	@echo "\n/userspace_demo"
	@$(MAKE) --no-print-directory -C userspace_demo clean
	@$(MAKE) --no-print-directory -C userspace_demo

