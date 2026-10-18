CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -std=c11
BUILD_DIR = build
BIN       = $(BUILD_DIR)/lsw2
SOURCES   = $(wildcard src/*.c)
OBJECTS   = $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all build test run clean help

all: build

build: $(BIN)

$(BIN): $(OBJECTS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

test: $(BIN)
	@sh tests/run-tests.sh

run: $(BIN)
	$(BIN) --version

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "Targets: all build test run clean"
-include $(OBJECTS:.o=.d)
