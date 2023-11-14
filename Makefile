PROGS = a.out

CFLAGS += -O3 -pipe -g -rdynamic
CFLAGS += -Werror -Wextra -Wall
CFLAGS += -DIOSUB_MAIN_C=$(IOSUB_DIR)/main.c

LDFLAGS += -lnuma

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
