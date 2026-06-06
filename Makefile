CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap
TARGET = demultiplexer

# Added handler.c to the source list
SRCS = main.c handler.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)