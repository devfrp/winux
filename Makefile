# === Makefile ===
# Projet : Winux — Exécuteur Windows natif transparent sur Linux
# Build system : GNU Make
# C standard   : C11
# Compilateur  : gcc (ou clang)
#
# Usage :
#   make              Compile winexec
#   make debug        Compile avec assertions et debug
#   make hello        Compile test_hello.exe (MinGW)
#   make stress       Compile test_stress.exe (MinGW)
#   make test         Compile et lance les tests
#   make install      Installe winexec dans /usr/local/bin
#   make clean        Nettoie les fichiers compilés

CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror \
            -Wno-unused-parameter -Wno-missing-field-initializers \
            -O2 -D_GNU_SOURCE
LDFLAGS  := -lpthread -lseccomp

MINGW_CC ?= x86_64-w64-mingw32-gcc
MINGW_CFLAGS := -std=c11 -O2 -s -nostartfiles -nostdlib
MINGW_LDFLAGS := -lkernel32

ifeq ($(DEBUG),1)
  CFLAGS += -g -O0 -DWINUX_DEBUG -fsanitize=address,undefined
  LDFLAGS += -fsanitize=address,undefined
endif

SRCDIR   := src
TESTDIR  := tests
INCDIR   := include
BUILDDIR := build
BINDIR   := $(BUILDDIR)/bin

# Sources
SOURCES := $(SRCDIR)/pe_loader.c \
           $(SRCDIR)/io_transparent.c \
           $(SRCDIR)/globals.c \
           $(SRCDIR)/nt_stubs.c \
           $(SRCDIR)/win32_bridge.c \
           $(SRCDIR)/memory_manager.c \
           $(SRCDIR)/thread_model.c \
           $(SRCDIR)/signal_passthrough.c \
           $(SRCDIR)/seccomp_filter.c \
           $(SRCDIR)/proc_compat.c \
           $(SRCDIR)/winexec.c

HEADERS := $(INCDIR)/winux.h \
           $(INCDIR)/pe_loader.h \
           $(INCDIR)/io_transparent.h \
           $(INCDIR)/nt_stubs.h \
           $(INCDIR)/win32_bridge.h \
           $(INCDIR)/memory_manager.h \
           $(INCDIR)/thread_model.h \
           $(INCDIR)/signal_passthrough.h \
           $(INCDIR)/seccomp_filter.h \
           $(INCDIR)/proc_compat.h

OBJECTS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))

TARGET      := $(BINDIR)/winexec
TEST_EXE    := $(BUILDDIR)/test_minimal.exe
HELLO_EXE   := $(BUILDDIR)/test_hello.exe
STRESS_EXE  := $(BUILDDIR)/test_stress.exe

# ==========================================================================
# Règles principales
# ==========================================================================

.PHONY: all clean test debug dirs exe hello stress all-test install uninstall \
        package-deb package-rpm package-tar package-all

DESTDIR ?=
PREFIX  ?= /usr/local
BINDIR_SYS  := $(DESTDIR)$(PREFIX)/bin
DOCDIR_SYS  := $(DESTDIR)$(PREFIX)/share/doc/winux

all: dirs $(TARGET)

debug:
	@$(MAKE) DEBUG=1 all

dirs:
	@mkdir -p $(BUILDDIR) $(BINDIR)

$(TARGET): $(OBJECTS)
	@echo "  LD    $@"
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "  Build complete: $@"

$(BUILDDIR)/%.o: $(SRCDIR)/%.c $(HEADERS) | dirs
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -I. -c -o $@ $<

# ==========================================================================
# .exe de test (PE Windows)
# ==========================================================================

exe: $(TEST_EXE)

$(TEST_EXE): tools/gen_minimal_exe.py
	@echo "  GEN   $@"
	@python3 $< -o $@

hello: $(HELLO_EXE)

$(HELLO_EXE): $(TESTDIR)/test_hello.c
	@echo "  MINGW $@"
	@$(MINGW_CC) $(MINGW_CFLAGS) -e WinMainCRTStartup \
		-o $@ $< $(MINGW_LDFLAGS) 2>&1 || \
		(echo "  NOTE : MinGW-w64 non trouvé. Installez :" ; \
		 echo "         sudo apt install gcc-mingw-w64-x86-64")

stress: $(STRESS_EXE)

$(STRESS_EXE): $(TESTDIR)/test_stress.c
	@echo "  MINGW $@"
	@$(MINGW_CC) $(MINGW_CFLAGS) -e WinMainCRTStartup \
		-o $@ $< $(MINGW_LDFLAGS) 2>&1 || \
		(echo "  NOTE : MinGW-w64 non trouvé.")

# ==========================================================================
# Tests
# ==========================================================================

test: all $(TEST_EXE) hello
	@echo "===================================================="
	@echo "  Winux Test Suite                                  "
	@echo "===================================================="
	@echo ""
	@echo "--- test_minimal.exe ---"
	@$(TARGET) $(TEST_EXE) 2>&1; echo "  Exit: $$?"
	@echo ""
	@echo "--- test_hello.exe ---"
	@$(TARGET) $(TESTDIR)/test_hello.c > /dev/null 2>&1 || true
	@$(TARGET) $(HELLO_EXE) 2>&1; echo "  Exit: $$?"
	@echo ""
	@echo "--- Checks ---"
	@echo -n "  /tmp/test.txt : " && cat /tmp/test.txt 2>/dev/null || echo "(run 'make stress && ./build/bin/winexec build/test_stress.exe')"
	@echo ""

# ==========================================================================
# Installation
# ==========================================================================

install: $(TARGET)
	@echo "  INSTALL $(TARGET) → $(BINDIR_SYS)/winexec"
	@mkdir -p $(BINDIR_SYS) $(DOCDIR_SYS)
	@install -m 755 $(TARGET) $(BINDIR_SYS)/winexec
	@install -m 644 README.md $(DOCDIR_SYS)/README.md
	@install -m 644 CHANGELOG.md $(DOCDIR_SYS)/CHANGELOG.md 2>/dev/null || true
	@install -m 644 LICENSE $(DOCDIR_SYS)/LICENSE 2>/dev/null || true
	@echo "  Install complete: winexec is now in $(BINDIR_SYS)/"

uninstall:
	@echo "  UNINSTALL"
	@rm -f $(BINDIR_SYS)/winexec
	@rm -rf $(DOCDIR_SYS)
	@echo "  Uninstall complete"

# ==========================================================================
# Packaging
# ==========================================================================

PKG_VERSION := 1.0.0
PKG_NAME    := winux
DISTDIR     := $(BUILDDIR)/dist
PKG_STAGING := $(DISTDIR)/staging

package-tar: $(TARGET)
	@echo "  PACK  tar.gz"
	@mkdir -p $(DISTDIR)
	@rm -rf $(PKG_STAGING)
	@mkdir -p $(PKG_STAGING)/usr/local/bin
	@mkdir -p $(PKG_STAGING)/usr/local/share/doc/winux
	@install -m 755 $(TARGET) $(PKG_STAGING)/usr/local/bin/winexec
	@install -m 644 README.md $(PKG_STAGING)/usr/local/share/doc/winux/README.md
	@install -m 644 CHANGELOG.md $(PKG_STAGING)/usr/local/share/doc/winux/CHANGELOG.md
	@install -m 644 LICENSE $(PKG_STAGING)/usr/local/share/doc/winux/LICENSE
	@cd $(PKG_STAGING) && tar czf ../../../$(DISTDIR)/$(PKG_NAME)-$(PKG_VERSION)-x86_64.tar.gz .
	@rm -rf $(PKG_STAGING)
	@echo "  Package: $(DISTDIR)/$(PKG_NAME)-$(PKG_VERSION)-x86_64.tar.gz"

package-deb: $(TARGET)
	@echo "  PACK  .deb"
	@mkdir -p $(DISTDIR)
	@rm -rf $(PKG_STAGING)
	@mkdir -p $(PKG_STAGING)/usr/local/bin
	@mkdir -p $(PKG_STAGING)/usr/local/share/doc/winux
	@install -m 755 $(TARGET) $(PKG_STAGING)/usr/local/bin/winexec
	@install -m 644 README.md $(PKG_STAGING)/usr/local/share/doc/winux/README.md
	@install -m 644 CHANGELOG.md $(PKG_STAGING)/usr/local/share/doc/winux/CHANGELOG.md
	@install -m 644 LICENSE $(PKG_STAGING)/usr/local/share/doc/winux/LICENSE
	@cp -r packaging/deb/DEBIAN $(PKG_STAGING)/
	@chmod 755 $(PKG_STAGING)/DEBIAN/postinst
	@dpkg-deb --build $(PKG_STAGING) $(DISTDIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb
	@rm -rf $(PKG_STAGING)
	@echo "  Package: $(DISTDIR)/$(PKG_NAME)_$(PKG_VERSION)_amd64.deb"

package-rpm: $(TARGET)
	@echo "  PACK  .rpm (requires rpmbuild)"
	@mkdir -p $(DISTDIR)
	@mkdir -p ~/rpmbuild/SOURCES
	@tar czf ~/rpmbuild/SOURCES/$(PKG_NAME)-$(PKG_VERSION).tar.gz \
		--transform 's,^,$(PKG_NAME)-$(PKG_VERSION)/,' \
		src include Makefile README.md CHANGELOG.md LICENSE 2>/dev/null || true
	@cp packaging/rpm/winux.spec ~/rpmbuild/SPECS/ 2>/dev/null || \
		mkdir -p ~/rpmbuild/SPECS && cp packaging/rpm/winux.spec ~/rpmbuild/SPECS/
	@rpmbuild -ba ~/rpmbuild/SPECS/winux.spec 2>&1 || \
		(echo "  NOTE: rpmbuild not available or failed." ; \
		 echo "  Install: sudo apt install rpm")
	@cp ~/rpmbuild/RPMS/x86_64/$(PKG_NAME)-*.rpm $(DISTDIR)/ 2>/dev/null || true
	@echo "  Package: $(DISTDIR)/$(PKG_NAME)-$(PKG_VERSION)-*.rpm"

package-all: package-tar package-deb
	@echo "  All packages built in $(DISTDIR)/"

# ==========================================================================
# Nettoyage
# ==========================================================================

clean:
	@echo "  CLEAN"
	@rm -rf $(BUILDDIR)
	@echo "  Clean complete"
