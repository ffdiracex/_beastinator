# ============================================================
# SYSSEC - System Security Tools for FreeBSD
# ============================================================
# 
# Targets:
#   all         - Build everything (default)
#   syssec      - Build main syssec tool
#   test        - Build and run tests
#   clean       - Remove object files and binaries
#   install     - Install to /usr/local/sbin
#   uninstall   - Remove from /usr/local/sbin
#
# Usage:
#   make                - Build everything
#   make syssec         - Build only main tool
#   make test           - Build and run tests
#   make clean          - Clean build files
#   sudo make install   - Install system-wide
# ============================================================

# ============================================================
# COMPILER SETTINGS
# ============================================================

CC = cc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lm -pthread

# Enable BSD features
CFLAGS += -D__BSD_VISIBLE=1
CFLAGS += -D_WANT_FREEBSD11_STAT=1
CFLAGS += -D_WANT_FREEBSD11_KINFO=1

# Debug mode (uncomment for debugging)
# CFLAGS += -g -DDEBUG
# LDFLAGS += -g

# ============================================================
# SOURCE FILES
# ============================================================

# Core system files
SYSCTL_SRCS = sysctl.c
SYSCTL_OBJS = $(SYSCTL_SRCS:.c=.o)

UTILS_SRCS = utils.c
UTILS_OBJS = $(UTILS_SRCS:.c=.o)

LOGGING_SRCS = logging.c
LOGGING_OBJS = $(LOGGING_SRCS:.c=.o)

CONFIG_SRCS = config.c
CONFIG_OBJS = $(CONFIG_SRCS:.c=.o)

REPORT_SRCS = report.c
REPORT_OBJS = $(REPORT_SRCS:.c=.o)

ALERT_SRCS = alert.c
ALERT_OBJS = $(ALERT_SRCS:.c=.o)

SCHEDULER_SRCS = scheduler.c
SCHEDULER_OBJS = $(SCHEDULER_SRCS:.c=.o)

SCANNER_SRCS = scanner.c
SCANNER_OBJS = $(SCANNER_SRCS:.c=.o)

# Main program
MAIN_SRCS = main.c
MAIN_OBJS = $(MAIN_SRCS:.c=.o)

# All object files
ALL_OBJS = $(SYSCTL_OBJS) $(UTILS_OBJS) $(LOGGING_OBJS) \
           $(CONFIG_OBJS) $(REPORT_OBJS) $(ALERT_OBJS) \
           $(SCHEDULER_OBJS) $(SCANNER_OBJS) $(MAIN_OBJS)

# ============================================================
# TARGETS
# ============================================================

TARGET = syssec

# ============================================================
# BUILD RULES
# ============================================================

all: $(TARGET)

$(TARGET): $(ALL_OBJS)
	$(CC) $(CFLAGS) -o $@ $(ALL_OBJS) $(LDFLAGS)
	@echo ""
	@echo "========================================"
	@echo "  SYSSEC build complete!"
	@echo "  Binary: ./$(TARGET)"
	@echo "  Run: ./$(TARGET) --help"
	@echo "========================================"
	@echo ""

# ============================================================
# COMPILATION RULES
# ============================================================

sysctl.o: sysctl.c sysctl.h
	$(CC) $(CFLAGS) -c $< -o $@

utils.o: utils.c utils.h syssec.h
	$(CC) $(CFLAGS) -c $< -o $@

logging.o: logging.c logging.h syssec.h
	$(CC) $(CFLAGS) -c $< -o $@

config.o: config.c config.h syssec.h utils.h
	$(CC) $(CFLAGS) -c $< -o $@

report.o: report.c report.h syssec.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

alert.o: alert.c alert.h syssec.h config.h utils.h
	$(CC) $(CFLAGS) -c $< -o $@

scheduler.o: scheduler.c scheduler.h syssec.h config.h
	$(CC) $(CFLAGS) -c $< -o $@

scanner.o: scanner.c scanner.h syssec.h config.h utils.h logging.h report.h
	$(CC) $(CFLAGS) -c $< -o $@

main.o: main.c syssec.h config.h logging.h report.h alert.h scheduler.h utils.h scanner.h
	$(CC) $(CFLAGS) -c $< -o $@

# ============================================================
# TEST TARGETS
# ============================================================

TEST_SRCS = test_sysctl.c
TEST_TARGET = test_sysctl

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(SYSCTL_OBJS) $(UTILS_OBJS) $(TEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(SYSCTL_OBJS) $(UTILS_OBJS) $(TEST_SRCS) $(LDFLAGS)

# ============================================================
# QUICK TEST (runs default scan)
# ============================================================

run: $(TARGET)
	./$(TARGET) scan

# ============================================================
# VERBOSE TEST
# ============================================================

run-verbose: $(TARGET)
	./$(TARGET) -v scan

# ============================================================
# INSTALL
# ============================================================

PREFIX = /usr/local
BINDIR = $(PREFIX)/sbin
CONFDIR = /etc/syssec

install: $(TARGET)
	@echo "Installing to $(BINDIR)..."
	mkdir -p $(BINDIR)
	cp $(TARGET) $(BINDIR)/
	chmod 755 $(BINDIR)/$(TARGET)
	@echo "Creating configuration directory..."
	mkdir -p $(CONFDIR)
	@if [ ! -f $(CONFDIR)/syssec.conf ]; then \
		echo "Creating default configuration..."; \
		cp syssec.conf.example $(CONFDIR)/syssec.conf 2>/dev/null || echo "No example config found"; \
	fi
	@echo ""
	@echo "========================================"
	@echo "  SYSSEC installed successfully!"
	@echo "  Binary: $(BINDIR)/$(TARGET)"
	@echo "  Config: $(CONFDIR)/syssec.conf"
	@echo "  Run: sudo $(BINDIR)/$(TARGET) scan"
	@echo "========================================"

# ============================================================
# UNINSTALL
# ============================================================

uninstall:
	@echo "Removing $(BINDIR)/$(TARGET)..."
	rm -f $(BINDIR)/$(TARGET)
	@echo "Done."

# ============================================================
# CLEAN
# ============================================================

clean:
	@echo "Cleaning build files..."
	rm -f $(ALL_OBJS) $(TARGET) $(TEST_TARGET)
	@echo "Done."

# ============================================================
# DEPENDENCY GENERATION
# ============================================================

depend:
	$(CC) -MM $(CFLAGS) *.c > .depend

-include .depend

# ============================================================
# HELP
# ============================================================

help:
	@echo "SYSSEC Makefile"
	@echo "========================================"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build everything (default)"
	@echo "  syssec         - Build main syssec tool"
	@echo "  test           - Build and run tests"
	@echo "  run            - Build and run default scan"
	@echo "  run-verbose    - Build and run verbose scan"
	@echo "  clean          - Remove object files and binaries"
	@echo "  install        - Install to /usr/local/sbin"
	@echo "  uninstall      - Remove from /usr/local/sbin"
	@echo "  depend         - Generate header dependencies"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Example:"
	@echo "  make            - Build everything"
	@echo "  make run        - Run default scan"
	@echo "  sudo make install - Install system-wide"
	@echo ""

# ============================================================
# PHONY TARGETS
# ============================================================

.PHONY: all clean test run run-verbose install uninstall depend help

# ============================================================
# END OF MAKEFILE
# ============================================================
