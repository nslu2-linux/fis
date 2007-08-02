NAME = fis
SRC = fis.c crc.c
OBJ = $(subst .c,.o, $(SRC))
CFLAGS = --std=c99

all: $(NAME)

%.d: %.c
	$(SHELL) -ec '$(CC) -M $(CPPFLAGS) $< \
		| sed '\''s/\($*\)\.o[ :]*/\1.o $@ : /g'\'' > $@; \
		[ -s $@ ] || rm -f $@'

ifneq ($(MAKECMDGOALS), clean)
-include $(SRC:.c=.d)
endif

$(NAME): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

clean:
	-rm -f $(NAME) *.d *.o

