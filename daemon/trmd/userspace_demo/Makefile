
NNG_Include_Folder := /opt/playground/nng/include
NNG_Library_Folder := /opt/devel/libnng

C_Includes := -I$(NNG_Include_Folder) -Ilibcitadel/include
C_Flags := -L$(NNG_Library_Folder) -lnng -Llibcitadel -lcitadel -pthread

all:
	$(CC) -o app userspace_app.c $(C_Includes) $(C_Flags)
