/*
 * logging.h - Logging system for SYSSEC tools
 * 
 * Provides structured logging with rotation support.
 * 
 * Copyright (c) 2026-2027 SYSSEC Project
 */

#ifndef SYSSEC_LOGGING_H
#define SYSSEC_LOGGING_H

#include "syssec.h"

/* ============================================================
 * LOG LEVELS
 * ============================================================ */

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARNING = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_DEBUG = 3,
    LOG_LEVEL_TRACE = 4
} syssec_log_level_t;

/* ============================================================
 * LOG FUNCTIONS
 * ============================================================ */

/*
 * log_init - Initialize logging system
 * 
 * @param log_dir: Directory for logs
 * @param log_file: Log file name
 * @param level: Log level
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t log_init(const char *log_dir, const char *log_file, 
                        syssec_log_level_t level);

/*
 * log_set_level - Set log level
 * 
 * @param level: New log level
 */
void log_set_level(syssec_log_level_t level);

/*
 * log_write - Write log message
 * 
 * @param level: Log level
 * @param format: Format string
 * @param ...: Format arguments
 */
void log_write(syssec_log_level_t level, const char *format, ...);

/*
 * log_error - Write error log
 */
#define log_error(...) log_write(LOG_LEVEL_ERROR, __VA_ARGS__)

/*
 * log_warning - Write warning log
 */
#define log_warning(...) log_write(LOG_LEVEL_WARNING, __VA_ARGS__)

/*
 * log_info - Write info log
 */
#define log_info(...) log_write(LOG_LEVEL_INFO, __VA_ARGS__)

/*
 * log_debug - Write debug log
 */
#define log_debug(...) log_write(LOG_LEVEL_DEBUG, __VA_ARGS__)

/*
 * log_trace - Write trace log
 */
#define log_trace(...) log_write(LOG_LEVEL_TRACE, __VA_ARGS__)

/*
 * log_rotate - Rotate log file
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t log_rotate(void);

/*
 * log_close - Close logging system
 */
void log_close(void);

#endif /* SYSSEC_LOGGING_H */
