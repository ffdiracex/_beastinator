/*
 * syssec.h - Main header for SYSSEC tools
 * 
 * This header includes all common definitions and utilities
 * used across the SYSSEC project.
 * 
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_H
#define SYSSEC_H

/* ============================================================
 * SYSTEM HEADERS
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

/* ============================================================
 * COLOR DEFINITIONS
 * ============================================================ */

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_DIM     "\033[2m"

/* ============================================================
 * MACROS
 * ============================================================ */

#define SYSSEC_VERSION "1.0.0"
#define SYSSEC_NAME    "SYSSEC - System Security Tools"

#define MAX_LINE       1024
#define MAX_PATH       512
#define MAX_NAME       256
#define MAX_STRING     1024
#define MAX_CHECKS     256
#define MAX_USERS      256
#define MAX_GROUPS     64

#ifndef CTL_MAXNAME
#define CTL_MAXNAME 32
#endif

/* ============================================================
 * STATUS CODES
 * ============================================================ */

typedef enum {
    SYSSEC_OK = 0,
    SYSSEC_ERR_NO_MEMORY = -1,
    SYSSEC_ERR_PERMISSION = -2,
    SYSSEC_ERR_NOT_FOUND = -3,
    SYSSEC_ERR_IO = -4,
    SYSSEC_ERR_INVALID = -5,
    SYSSEC_ERR_BUF_TOO_SMALL = -6,
    SYSSEC_ERR_NOT_IMPLEMENTED = -7,
    SYSSEC_ERR_TIMEOUT = -8
} syssec_error_t;

/* ============================================================
 * SEVERITY LEVELS
 * ============================================================ */

typedef enum {
    SEVERITY_INFO = 0,
    SEVERITY_WARNING = 1,
    SEVERITY_CRITICAL = 2,
    SEVERITY_ERROR = 3
} syssec_severity_t;

/* ============================================================
 * CHECK STATUS
 * ============================================================ */

typedef enum {
    STATUS_PASS = 0,
    STATUS_WARN = 1,
    STATUS_FAIL = 2,
    STATUS_UNKNOWN = 3
} syssec_status_t;

/* ============================================================
 * HELPER FUNCTIONS
 * ============================================================ */

/* Convert severity to string */
static inline const char* syssec_severity_str(syssec_severity_t sev) {
    switch (sev) {
        case SEVERITY_INFO:     return "INFO";
        case SEVERITY_WARNING:  return "WARNING";
        case SEVERITY_CRITICAL: return "CRITICAL";
        case SEVERITY_ERROR:    return "ERROR";
        default:                return "UNKNOWN";
    }
}

/* Convert status to string */
static inline const char* syssec_status_str(syssec_status_t status) {
    switch (status) {
        case STATUS_PASS:   return "PASS";
        case STATUS_WARN:   return "WARN";
        case STATUS_FAIL:   return "FAIL";
        default:            return "UNKNOWN";
    }
}

/* Get color for status */
static inline const char* syssec_status_color(syssec_status_t status) {
    switch (status) {
        case STATUS_PASS:   return COLOR_GREEN;
        case STATUS_WARN:   return COLOR_YELLOW;
        case STATUS_FAIL:   return COLOR_RED;
        default:            return COLOR_BLUE;
    }
}

/* Get color for severity */
static inline const char* syssec_severity_color(syssec_severity_t sev) {
    switch (sev) {
        case SEVERITY_INFO:     return COLOR_BLUE;
        case SEVERITY_WARNING:  return COLOR_YELLOW;
        case SEVERITY_CRITICAL: return COLOR_RED;
        case SEVERITY_ERROR:    return COLOR_MAGENTA;
        default:                return COLOR_RESET;
    }
}

/* Check if running as root */
static inline int syssec_is_root(void) {
    return geteuid() == 0;
}

/* Get current username */
static inline const char* syssec_get_username(void) {
    struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_name : "unknown";
}

/* Format time */
static inline void syssec_format_time(time_t t, char *buf, size_t size) {
    struct tm *tm = localtime(&t);
    if (tm) {
        strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm);
    } else {
        snprintf(buf, size, "unknown");
    }
}

/* Print banner */
static inline void syssec_banner(void) {
    printf(COLOR_CYAN "╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    SYSSEC - System Security Tools                  ║\n");
    printf("║                    FreeBSD Security Toolkit                        ║\n");
    printf("║                    Version %s                                      ║\n", SYSSEC_VERSION);
    printf("╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
}

#endif /* SYSSEC_H */
