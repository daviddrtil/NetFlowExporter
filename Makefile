# ISA - project
# Brief:	Makefile to compile and build project
# Author: 	David Drtil <xdrtil03@stud.fit.vutbr.cz>
# Date:		2022-10-01

CC=gcc
CFLAGS=-std=gnu11 -Wall -Wunused-value -Wno-unknown-pragmas
FILES=./src/*.c ./src/*.h
EXECUTABLE=flow

$(EXECUTABLE): $(FILES)
		$(CC) $(CFLAGS) $(FILES) -o $(EXECUTABLE) -lpcap

tar: $(FILES) Makefile Readme.md
	tar cvf xdrtil03.tar $^

clean:
	rm -f $(EXECUTABLE)
