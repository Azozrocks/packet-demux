CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap
TARGET = demultiplexer

# Add handler.c to this list once Person 2 provides it
SRCS = main.c 
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)