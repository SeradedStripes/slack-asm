SOURCES := $(filter-out src/rsa_test.asm src/prf_test.asm src/gcm_test.asm,$(wildcard src/*.asm))
OBJS := $(patsubst src/%.asm,src/%.o,$(SOURCES))

NASM := nasm
NASMFLAGS := -f elf64
LD := ld

.PHONY: all clean test run rsa_test gcm_test

all: slack

slack: $(OBJS)
	$(LD) -o $@ $(OBJS)

rsa_test: src/rsa_test.o src/rsa.o src/x509.o
	$(LD) -o $@ $^

gcm_test: src/gcm_test.o src/gcm.o src/crypto.o
	$(LD) -o $@ $^

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) src/prf_test.o src/rsa_test.o src/gcm_test.o slack rsa_test gcm_test

test: all
	@echo "Running tests (binary: ./slack)"
	./slack

run: all
	@echo "Running slack"
	./slack

