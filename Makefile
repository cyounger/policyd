CC = gcc
DEPS = 
SRCS = policyd.c
OBJS = $(SRCS:.c=.o)
# gnu99 needed for pthread_rwlock_t and pthread_barrier_t
CFLAGS = -g -std=gnu99 -Wall -Werror $(shell pkg-config --cflags libuv)
LDFLAGS = $(shell pkg-config --libs libuv)
EXEC = policyd

all : $(EXEC)

$(EXEC) : $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o : %.c $(DEPS)
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY : clean all
clean :
	rm -f *.o
	rm -f $(EXEC)
