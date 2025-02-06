# A simple Makefile, to build run: make all
TARGET	= test

CC	= gcc
#compiler flags here
CFLAGS = -O3 -Wall -Wextra

#linker flags here
LFLAGS = -Wall

SRCDIR	= src

SOURCES  := $(wildcard $(SRCDIR)/src/*.c)
INCLUDES := $(wildcard $(SRCDIR)/src/*.h))
OBJECTS  := $(SOURCES:$(SRCDIR)/src/%.c=$(SRCDIR)/src/%.o)

.PHONY: all clean remove
all: ${TARGET}

$(TARGET): $(OBJECTS)
	@$(CC) -o $@ $(LFLAGS) $(OBJECTS)

$(OBJECTS): $(SRCDIR)/src/%.o : $(SRCDIR)/src/%.c
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@$ rm -f $(OBJECTS)

remove: clean
	@$ rm -f $(TARGET)
