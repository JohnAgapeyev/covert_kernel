BASEFLAGS := -Wall -Wextra -pedantic -pipe -std=c11
DEBUGFLAGS := -g -O0
RELEASEFLAGS := -s -O3 -march=native -flto -DNDEBUG
LIBFLAGS := -lcrypto -lssl

obj-m += covert_module.o

all debug release: userspace.o server.o
	$(CC) $(CUSTOM_CFLAGS) userspace.o $(LIBFLAGS) -o userspace.elf
	$(CC) $(CUSTOM_CFLAGS) server.o $(LIBFLAGS) -o server.elf
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Prevent clean from trying to do anything with a file called clean
.PHONY: clean

clean:
	$(RM) userspace.o server.o covert_module.o userspace.elf server.elf
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#Check if in debug mode and set the appropriate compile flags
ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(DEBUGFLAGS))
endif

%.o: %.c
	$(CC) $(CUSTOM_CFLAGS) -c $<
