

Object_Files := src/init.o

all: libcitadel.a

libcitadel.a: %: $(Object_Files)
	$(AR) rcs $@ $(Object_Files)

%.o: %.c
	$(CC) -g -O -c -o $@ $< 

.PHONY: clean
clean:
	@rm -f **/*.o