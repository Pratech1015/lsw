# LSW - Linux Subsystem for Windows
# Copyright (c) 2026 LSW Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

PREFIX       ?= /usr
DATADIR      ?= $(PREFIX)/share
SYSCONFDIR   ?= /etc
VARDIR       ?= /var/lib/lsw
BINDIR       ?= $(PREFIX)/bin
LIBDIR       ?= $(PREFIX)/lib
LOCALSTATEDIR?= /var

CC          ?= gcc
CFLAGS      ?= -O2
CFLAGS      += -Wall -Wextra -std=c11 -fPIC
CFLAGS      += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
CPPFLAGS    += -I$(CURDIR)/ntll/include
LDFLAGS     ?=
LDLIBS      += -lpthread -lm

VERSION      = 1.0.0
BUILD       ?= release
BUILD_DIR    = build
BIN_DIR      = $(BUILD_DIR)/bin
# EDITION selectively installs one Windows version (lsw-win-11 / lsw-win-10)
EDITION     ?= all

NTLL_SRCS    = ntll/runtime.c ntll/pe_loader.c ntll/syscall.c ntll/process.c \
               ntll/memory.c ntll/kernel32.c ntll/dispatch.c ntll/strings.c \
               ntll/registry.c ntll/ntdll.c ntll/cmd.c ntll/tools.c ntll/mounts.c \
               ntll/ucrtbase.c
NTLL_OBJS    = $(patsubst ntll/%.c,$(BUILD_DIR)/ntll/%.o,$(NTLL_SRCS))

LSWD_SRCS    = lswd/lswd.c
LSWD_OBJS    = $(patsubst lswd/%.c,$(BUILD_DIR)/lswd/%.o,$(LSWD_SRCS))

DIST_TARGETS = lsw lswd lsw-init lsw-runtime
DOCS         = README.md LICENSE

BIN_LSW_RUNTIME = $(BIN_DIR)/lsw-runtime
BIN_LSWD        = $(BIN_DIR)/lswd
BIN_LSW_INIT    = $(BIN_DIR)/lsw-init

all: $(BIN_LSW_RUNTIME) $(BIN_LSWD) $(BIN_LSW_INIT)
	@echo
	@echo "  LSW build complete"
	@echo "  Run 'sudo make install' to install."

$(BUILD_DIR)/ntll/%.o: ntll/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/lswd/%.o: lswd/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BIN_LSW_RUNTIME): $(NTLL_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) -o $@ $(NTLL_OBJS) $(LDFLAGS) $(LDLIBS)

$(BIN_LSWD): $(LSWD_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) -o $@ $(LSWD_OBJS) $(LDFLAGS) $(LDLIBS)

$(BIN_LSW_INIT): lsw-init/lsw-init.c
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

# CLI wrapper script -> POSIX shell friendly
lsw:
	@printf 'error: use `lsw` from the installed binary, or run `make install`\n' >&2
	@exit 1

install: all
	install -d $(DESTDIR)$(LIBDIR)/lsw
	install -d $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(DATADIR)/lsw
	install -d $(DESTDIR)$(SYSCONFDIR)/lsw
	install -d $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-11
	install -d $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-10
	install -d $(DESTDIR)$(LOCALSTATEDIR)/lib/lsw

	# Binaries
	install -m 0755 $(BIN_DIR)/lsw-runtime $(DESTDIR)$(LIBDIR)/lsw/lsw-runtime
	ln -sf $(LIBDIR)/lsw/lsw-runtime $(DESTDIR)$(BINDIR)/lsw-runtime
	install -m 0755 $(BIN_DIR)/lswd $(DESTDIR)$(BINDIR)/lswd
	install -m 0755 $(BIN_DIR)/lsw-init $(DESTDIR)$(LIBDIR)/lsw/lsw-init
	ln -sf $(LIBDIR)/lsw/lsw-init $(DESTDIR)$(BINDIR)/lsw-init

	# CLI scripts (flat: installed common.sh must be at $(LIBDIR)/lsw/common.sh)
	install -m 0755 src/lsw $(DESTDIR)$(BINDIR)/lsw
	install -d $(DESTDIR)$(LIBDIR)/lsw
	install -m 0644 lib/common.sh $(DESTDIR)$(LIBDIR)/lsw/common.sh
	install -m 0644 lib/install.sh $(DESTDIR)$(LIBDIR)/lsw/install.sh
	install -m 0644 lib/manage.sh $(DESTDIR)$(LIBDIR)/lsw/manage.sh
	install -m 0644 lib/runner.sh $(DESTDIR)$(LIBDIR)/lsw/runner.sh

	# Distro manifests & templates
	install -m 0644 distros/windows-11/manifest.json $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-11/manifest.json
	install -m 0644 distros/windows-10/manifest.json $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-10/manifest.json
	install -m 0644 distros/windows-11/setup.sh $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-11/setup.sh
	install -m 0644 distros/windows-10/setup.sh $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-10/setup.sh

	# Bundled Windows rootfs (System32 CLI executables) shipped with the distro
	@if [ -d distros/windows-11/rootfs ]; then \
		cp -a distros/windows-11/rootfs $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-11/rootfs; \
	fi
	@if [ -d distros/windows-10/rootfs ]; then \
		cp -a distros/windows-10/rootfs $(DESTDIR)$(SYSCONFDIR)/lsw/distros/windows-10/rootfs; \
	fi

	# Edition locking: an edition-scoped package (lsw-win-11 / lsw-win-10)
	# writes /etc/lsw/edition so 'lsw' targets a single Windows version.
	@if [ "$(EDITION)" != "all" ]; then \
		echo "$(EDITION)" > $(DESTDIR)$(SYSCONFDIR)/lsw/edition; \
		echo "  Edition locked to: $(EDITION)"; \
	fi

	# Bash completion
	install -d $(DESTDIR)$(DATADIR)/bash-completion/completions
	install -m 0644 bash-completion/lsw $(DESTDIR)$(DATADIR)/bash-completion/completions/lsw

	# Config
	install -m 0644 config/lsw.conf $(DESTDIR)$(SYSCONFDIR)/lsw/lsw.conf
	install -m 0644 config/wsl.conf.example $(DESTDIR)$(SYSCONFDIR)/lsw/wsl.conf.example

	# Docs
	install -m 0644 README.md $(DESTDIR)$(DATADIR)/lsw/README.md
	install -m 0644 LICENSE $(DESTDIR)$(DATADIR)/lsw/LICENSE

	@echo
	@echo "  LSW installed."
	@echo "  Next:  lsw --install windows-11"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lsw
	rm -f $(DESTDIR)$(BINDIR)/lswd
	rm -f $(DESTDIR)$(BINDIR)/lsw-runtime
	rm -f $(DESTDIR)$(BINDIR)/lsw-init
	rm -rf $(DESTDIR)$(LIBDIR)/lsw
	rm -f $(DESTDIR)$(DATADIR)/bash-completion/completions/lsw
	rm -rf $(DESTDIR)$(SYSCONFDIR)/lsw

clean:
	rm -rf $(BUILD_DIR)

distclean: clean
	rm -rf packaging/build

test: all
	@echo "  Running tests..."
	./tests/run-tests.sh || exit 1

# Packaging helpers
pkg-deb: all
	cd packaging && ./build-deb.sh ../$(VERSION)

pkg-rpm: all
	cd packaging && ./build-rpm.sh ../$(VERSION)

pkg-arch: all
	cd packaging && makepkg -f

# Source tarball used by the curl quick-start installer and releases
PACKAGE_NAME = lsw-$(VERSION)

release:
	@echo "  Preparing $(PACKAGE_NAME).tar.gz ..."
	@rm -rf $(BUILD_DIR)/release/$(PACKAGE_NAME)
	@mkdir -p $(BUILD_DIR)/release/$(PACKAGE_NAME)
	@tar --exclude='.git' --exclude='build' --exclude='build-tests' \
	     --exclude='*.o' --exclude='lsw-runtime' --exclude='lswd' \
	     -cf - . | (cd $(BUILD_DIR)/release/$(PACKAGE_NAME) && tar -xf -)
	@cd $(BUILD_DIR)/release && tar -czf $(PACKAGE_NAME).tar.gz $(PACKAGE_NAME)
	@echo "  -> $(BUILD_DIR)/release/$(PACKAGE_NAME).tar.gz"

.PHONY: all clean distclean install uninstall test lsw pkg-deb pkg-rpm pkg-arch release
.SUFFIXES: .c .o