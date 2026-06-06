CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap
TARGET = demux

# Include capture.c and main.c. Person 2 will add demux.c here later.
SRCS = main.c capture.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)