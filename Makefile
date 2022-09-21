OBJS	= main.o capture.o
SOURCE	= main.c capture.c
HEADER	= capture.h bootp.h
OUT	= sniffer
CC	 = gcc
FLAGS	 = -g -c -Wall
LFLAGS	 = -lpcap

all: $(OBJS)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS)

main.o: main.c
	$(CC) $(FLAGS) main.c -lcunit

capture.o: capture.c
	$(CC) $(FLAGS) capture.c -lcunit


clean:
	rm -f $(OBJS) $(OUT)