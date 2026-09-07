# ============================================================
# SYSSEC - System Security Tools for FreeBSD
# ============================================================

CC = cc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lm -pthread

# Source files
SRCS = scanner.c config.c logging.c report.c alert.c utils.c
OBJS = $(SRCS:.c=.o)

TARGET = syssec_scanner

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c syssec.h config.h logging.h report.h alert.h utils.h
	$(CC) $(CFLAGS) -c $< -o $@

# Standalone tools
security_audit: security_audit.c config.c logging.c report.c alert.c utils.c
	$(CC) $(CFLAGS) -o $@ security_audit.c config.c logging.c report.c alert.c utils.c $(LDFLAGS)

clean:
	rm -f $(TARGET) security_audit $(OBJS) *.o

install: all
	mkdir -p /usr/local/sbin
	mkdir -p /etc/syssec
	cp $(TARGET) security_audit /usr/local/sbin/
	chmod 755 /usr/local/sbin/*

uninstall:
	cd /usr/local/sbin && rm -f $(TARGET) security_audit

.PHONY: all clean install uninstall
