NASM := nasm
NASMFLAGS := -f elf64 -I src/
LD := ld

.PHONY: all clean test run rsa_test gcm_test

# ---- Main slack binary ----
SLACK_SRCS := $(filter-out src/aes_test.asm src/rsa_test.asm src/prf_test.asm src/gcm_test.asm src/httpbin_test.asm,$(wildcard src/*.asm))
SLACK_OBJS := $(patsubst src/%.asm,src/%.o,$(SLACK_SRCS))

all: slack

slack: $(SLACK_OBJS)
	$(LD) -o $@ $(SLACK_OBJS)

# ---- Test runner ----
CORE_SRCS := $(filter-out src/slack.asm src/test.asm src/gcm_test.asm src/prf_test.asm src/rsa_test.asm src/cmd.asm src/slash-commands.asm src/commands.asm,$(wildcard src/*.asm))
CORE_OBJS := $(patsubst src/%.asm,src/%.o,$(CORE_SRCS))

TEST_SRCS := $(wildcard test/*.asm)
TEST_OBJS := $(patsubst test/%.asm,test/%.o,$(TEST_SRCS))

test_runner: $(TEST_OBJS) $(CORE_OBJS)
	$(LD) -o $@ $^

test: test_runner
	./test_runner

# ---- Standalone test binaries ----
rsa_test: src/rsa_test.o src/rsa.o src/x509.o
	$(LD) -o $@ $^

gcm_test: src/gcm_test.o src/gcm.o src/crypto.o
	$(LD) -o $@ $^

# ---- Generic assembly -> object rule ----
%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(SLACK_OBJS) src/test.o src/cmd.o src/slash-commands.o src/commands.o slack test_runner
	rm -f $(TEST_OBJS)
	rm -f src/aes_test.o src/prf_test.o src/rsa_test.o src/gcm_test.o
	rm -f rsa_test gcm_test aes_test httpbin_test

run: slack
	@echo "Running slack"
	./slack

