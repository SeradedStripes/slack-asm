SOURCES := $(wildcard *.asm)
OBJS := $(SOURCES:.asm=.o)

NASM := nasm
NASMFLAGS := -f elf64
LD := ld

.PHONY: all clean

all: slack

slack: $(OBJS)
	$(LD) -o $@ $(OBJS)

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) slack
