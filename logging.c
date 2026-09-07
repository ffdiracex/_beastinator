/*
 * logging.c - Logging system for SYSSEC tools
 * 
 * Provides structured logging with rotation support.
 * 
 * Compile: cc -Wall -Wextra -O2 -c logging.c -o logging.o
 */

#define __BSD_VISIBLE 1

#include "syssec.h"
#include "logging.h"
#include "utils.h"
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

static struct {
    char log_dir[MAX_PATH];
    char log_file[MAX_NAME];
    char log_path[MAX_PATH];
    syssec_log_level_t level;
    int initialized;
    int fd;
    pthread_mutex_t lock;
    size_t size;
    size_t max_size;
} log_state = {
    .log_dir = "/var/log/syssec",
    .log_file = "syssec.log",
    .level = LOG_LEVEL_INFO,
    .initialized = 0,
    .fd = -1,
    .max_size = 10 * 1024 * 1024  /* 10 MB */
};

/* ============================================================
 * INTERNAL FUNCTIONS
 * ============================================================ */

static const char* log_level_string(syssec_log_level_t level) {
    switch (level) {
        case LOG_LEVEL_ERROR:   return "ERROR";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_INFO:    return "INFO";
        case LOG_LEVEL_DEBUG:   return "DEBUG";
        case LOG_LEVEL_TRACE:   return "TRACE";
        default:                return "UNKNOWN";
    }
}

static int log_rotate_file(void) {
    char old_path[MAX_PATH];
    char new_path[MAX_PATH];
    struct stat st;
    
    if (log_state.fd < 0) {
        return -1;
    }
    
    /* Close current file */
    close(log_state.fd);
    log_state.fd = -1;
    
    /* Check current file size */
    if (stat(log_state.log_path, &st) == 0) {
        if (st.st_size < log_state.max_size) {
            /* Reopen the file */
            log_state.fd = open(log_state.log_path, 
                               O_WRONLY | O_CREAT | O_APPEND, 0644);
            return log_state.fd >= 0 ? 0 : -1;
        }
    }
    
    /* Rotate: move current to .old */
    snprintf(old_path, sizeof(old_path), "%s.old", log_state.log_path);
    rename(log_state.log_path, old_path);
    
    /* Create new file */
    log_state.fd = open(log_state.log_path, 
                       O_WRONLY | O_CREAT | O_APPEND, 0644);
    
    /* Write rotation message */
    if (log_state.fd >= 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), 
                "\n=== LOG ROTATED: %s ===\n\n", 
                ctime(&(time_t){time(NULL)}));
        write(log_state.fd, msg, strlen(msg));
    }
    
    return log_state.fd >= 0 ? 0 : -1;
}

static void log_write_raw(const char *buffer) {
    if (log_state.fd < 0) return;
    
    pthread_mutex_lock(&log_state.lock);
    write(log_state.fd, buffer, strlen(buffer));
    fsync(log_state.fd);
    
    /* Check if rotation needed */
    struct stat st;
    if (stat(log_state.log_path, &st) == 0) {
        if (st.st_size > log_state.max_size) {
            log_rotate_file();
        }
    }
    pthread_mutex_unlock(&log_state.lock);
}

/* ============================================================
 * PUBLIC FUNCTIONS
 * ============================================================ */

syssec_error_t log_init(const char *log_dir, const char *log_file, 
                        syssec_log_level_t level) {
    char path[MAX_PATH];
    struct stat st;
    
    if (!log_dir) log_dir = "/var/log/syssec";
    if (!log_file) log_file = "syssec.log";
    
    /* Create log directory if it doesn't exist */
    if (util_create_dir(log_dir, 0755) != SYSSEC_OK) {
        /* Try /tmp as fallback */
        log_dir = "/tmp";
        util_create_dir("/tmp/syssec", 0755);
        snprintf(path, sizeof(path), "/tmp/syssec/%s", log_file);
    } else {
        snprintf(path, sizeof(path), "%s/%s", log_dir, log_file);
    }
    
    /* Initialize state */
    pthread_mutex_init(&log_state.lock, NULL);
    strncpy(log_state.log_dir, log_dir, sizeof(log_state.log_dir) - 1);
    strncpy(log_state.log_file, log_file, sizeof(log_state.log_file) - 1);
    strncpy(log_state.log_path, path, sizeof(log_state.log_path) - 1);
    log_state.level = level;
    log_state.initialized = 1;
    
    /* Open log file */
    log_state.fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_state.fd < 0) {
        return SYSSEC_ERR_IO;
    }
    
    return SYSSEC_OK;
}

void log_set_level(syssec_log_level_t level) {
    log_state.level = level;
}

void log_write(syssec_log_level_t level, const char *format, ...) {
    char buffer[4096];
    char time_str[64];
    time_t now;
    struct tm *tm;
    va_list args;
    
    if (!log_state.initialized) {
        /* Auto-initialize if not already done */
        log_init(NULL, NULL, LOG_LEVEL_INFO);
    }
    
    if (level > log_state.level) {
        return;
    }
    
    /* Get timestamp */
    now = time(NULL);
    tm = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
    
    /* Format message */
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    /* Write to file */
    char line[4096];
    snprintf(line, sizeof(line), "[%s] %-7s %s\n", 
             time_str, log_level_string(level), buffer);
    log_write_raw(line);
    
    /* Also output to stderr if critical or error */
    if (level <= LOG_LEVEL_ERROR) {
        fprintf(stderr, "%s", line);
    }
}

void log_close(void) {
    if (log_state.fd >= 0) {
        close(log_state.fd);
        log_state.fd = -1;
    }
    pthread_mutex_destroy(&log_state.lock);
    log_state.initialized = 0;
}

syssec_error_t log_rotate(void) {
    if (!log_state.initialized) {
        return SYSSEC_ERR_NOT_IMPLEMENTED;
    }
    return log_rotate_file() == 0 ? SYSSEC_OK : SYSSEC_ERR_IO;
}
