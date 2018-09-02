BASEFLAGS := -Wall -Wextra -pedantic -pipe -std=c11
DEBUGFLAGS := -g -O0
RELEASEFLAGS := -s -O3 -march=native -flto -DNDEBUG
LIBFLAGS := -lcrypto -lssl
APPNAME := userspace
SRCWILD := userspace.c
SRCOBJS := userspace.o
EXEC := $(APPNAME).elf
DEPS := $(EXEC).d

obj-m += covert_module.o

all debug releas: $(SRCOBJS)
	$(CC) $(CUSTOM_CFLAGS) $^ $(LIBFLAGS) -o $(EXEC)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Prevent clean from trying to do anything with a file called clean
.PHONY: clean

clean:
	$(RM) $(EXEC) $(DEPS) $(wildcard *.d*) $(*.o)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

#Check if in debug mode and set the appropriate compile flags
ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CUSTOM_CFLAGS := $(BASEFLAGS) $(DEBUGFLAGS))
endif

%.o: %.c
	$(CC) $(CUSTOM_CFLAGS) -c $<
