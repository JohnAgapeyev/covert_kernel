BASEFLAGS := -Wall Wextra -pedantic -pipe -std=c11
DEBUGFLAGS := -g -O0
RELEASEFLAGS := -s -O3 -march=native -flto -DNDEBUG
LDFLAGS := -lcrypto -lssl
APPNAME := userspace
SRCWILD := userspace.c
SRCOBJS := userspace.o
EXEC := $(APPNAME).elf
DEPS := $(EXEC).d

obj-m += covert_module.o

all: $(SRCOBJS)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $(EXEC)

# Prevent clean from trying to do anything with a file called clean
.PHONY: clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) $(EXEC) $(DEPS) $(wildcard *.d*) $(*.o)

# Add the dependencies into make and don't throw an error if it doesn't exist
# Also don't generate dependency file during a clean
ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

#Check if in debug mode and set the appropriate compile flags
ifeq (,$(filter debug, $(MAKECMDGOALS)))
$(eval CFLAGS := $(BASEFLAGS) $(RELEASEFLAGS))
else
$(eval CFLAGS := $(BASEFLAGS) $(DEBUGFLAGS))
endif

# Create dependency file for make and manually adjust it silently to work with other directories
$(DEPS): $(SRCWILD)
# Compile the non-system dependencies and store it in execname.d
	@$(CC) -MM $(CFLAGS) $(SRCWILD) > $(DEPS)

# Use implicit rule to compile individual source files
