PROGS = a.out

CFLAGS += -O3 -pipe -g
ifeq ($(shell $(CC) -v 2>&1 | grep "gcc" 2>&1 | xargs -n 1 test -z && echo 0 || echo 1), 1)
CFLAGS += -rdynamic
else ifeq ($(shell $(CC) -v 2>&1 | grep "clang" 2>&1 | xargs -n 1 test -z && echo 0 || echo 1), 1)
endif
CFLAGS += -Werror -Wextra -Wall
CFLAGS += -DIOSUB_MAIN_C=$(IOSUB_DIR)/main.c
CFLAGS += $(APP_EXTRA_CFLAGS)

OSNAME = $(shell uname -s)

ifeq ($(OSNAME),Linux)
LDFLAGS += -lnuma
else ifeq ($(OSNAME),FreeBSD)
endif

LDFLAGS += $(APP_EXTRA_LDFLAGS)

C_OBJS = main.o

OBJS += $(C_OBJS)

CLEANFILES = $(PROGS) $(OBJS)

.PHONY: all
all: $(PROGS)

include $(IOSUB_DIR)/build.mk

$(OBJS): $(IOSUB_DEP)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
