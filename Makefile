# libplum

NAME=libplum
CC=$(CROSS)gcc
AR=$(CROSS)ar
RM=rm -f
CFLAGS=-O2 -pthread -fPIC
LDFLAGS=-pthread
LIBS=

INCLUDES=-Iinclude/plum
LDLIBS=

ifneq ($(LIBS), "")
INCLUDES+=$(if $(LIBS),$(shell pkg-config --cflags $(LIBS)),)
LDLIBS+=$(if $(LIBS), $(shell pkg-config --libs $(LIBS)),)
endif

SRCS=$(shell printf "%s " src/*.c)
OBJS=$(subst .c,.o,$(SRCS))

EXAMPLE_SRCS=$(shell printf "%s " example/*.c)
EXAMPLE_OBJS=$(subst .c,.o,$(EXAMPLE_SRCS))

all: $(NAME).a $(NAME).so example.out

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -MMD -MP -o $@ -c $<

example/%.o: example/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -Iinclude -MMD -MP -o $@ -c $<

-include $(subst .c,.d,$(SRCS))

$(NAME).a: $(OBJS)
	$(AR) crf $@ $(OBJS)

$(NAME).so: $(OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $(OBJS) $(LDLIBS)

example.out: $(NAME).a $(EXAMPLE_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(EXAMPLE_OBJS) $(LDLIBS) $(NAME).a

clean:
	-$(RM) include/plum/*.d *.d
	-$(RM) src/*.o src/*.d
	-$(RM) example/*.o example/*.d

dist-clean: clean
	-$(RM) $(NAME).a
	-$(RM) $(NAME).so
	-$(RM) example.out
	-$(RM) include/*~
	-$(RM) src/*~
	-$(RM) example/*~

