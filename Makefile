PROGS = a.out

CFLAGS += -O3 -pipe -g -rdynamic
CFLAGS += -Werror -Wextra -Wall

LDFLAGS +=

C_OBJS = main.o

OBJS += $(C_OBJS)

CLEANFILES = $(PROGS) $(OBJS)

.PHONY: all
all: $(PROGS)

include $(IOSUB_MK)

$(OBJS): $(IOSUB_DEP)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
