SOURCES := $(filter-out src/rsa_test.asm src/prf_test.asm,$(wildcard src/*.asm))
OBJS := $(patsubst src/%.asm,src/%.o,$(SOURCES))

NASM := nasm
NASMFLAGS := -f elf64
LD := ld

.PHONY: all clean test run rsa_test

all: slack

slack: $(OBJS)
	$(LD) -o $@ $(OBJS)

rsa_test: src/rsa_test.o src/rsa.o src/x509.o
	$(LD) -o $@ $^

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) src/rsa_test.o slack rsa_test

test: all
	@echo "Running tests (binary: ./slack)"
	./slack

run: all
	@echo "Running slack"
	./slack

