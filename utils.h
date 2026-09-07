o/*
 * utils.h - Utility functions for SYSSEC tools
 * 
 * Provides common helper functions used across the project.
 * 
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_UTILS_H
#define SYSSEC_UTILS_H

#include "syssec.h"

/* ============================================================
 * STRING UTILITIES
 * ============================================================ */

/*
 * util_trim - Trim whitespace from string
 * 
 * @param str: String to trim (modified in place)
 * 
 * Returns: Pointer to trimmed string
 */
char* util_trim(char *str);

/*
 * util_strdup - Safe strdup with error handling
 * 
 * @param str: String to duplicate
 * 
 * Returns: Duplicated string or NULL on error
 */
char* util_strdup(const char *str);

/*
 * util_join_path - Join path components
 * 
 * @param dest: Output buffer
 * @param size: Buffer size
 * @param parts: Path components (NULL terminated)
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_join_path(char *dest, size_t size, const char *parts, ...);

/*
 * util_safe_filename - Convert string to safe filename
 * 
 * @param src: Source string
 * @param dest: Output buffer
 * @param size: Buffer size
 */
void util_safe_filename(const char *src, char *dest, size_t size);

/* ============================================================
 * FILE UTILITIES
 * ============================================================ */

/*
 * util_file_exists - Check if file exists
 * 
 * @param path: File path
 * 
 * Returns: 1 if exists, 0 if not
 */
int util_file_exists(const char *path);

/*
 * util_dir_exists - Check if directory exists
 * 
 * @param path: Directory path
 * 
 * Returns: 1 if exists, 0 if not
 */
int util_dir_exists(const char *path);

/*
 * util_create_dir - Create directory (recursive)
 * 
 * @param path: Directory path
 * @param mode: Directory permissions
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_create_dir(const char *path, mode_t mode);

/*
 * util_read_file - Read entire file into memory
 * 
 * @param path: File path
 * @param data: Output buffer (will be allocated)
 * @param size: Output size
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_read_file(const char *path, char **data, size_t *size);

/*
 * util_write_file - Write data to file
 * 
 * @param path: File path
 * @param data: Data to write
 * @param size: Data size
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_write_file(const char *path, const char *data, size_t size);

/* ============================================================
 * SYSTEM UTILITIES
 * ============================================================ */

/*
 * util_get_hostname - Get system hostname
 * 
 * @param buffer: Output buffer
 * @param size: Buffer size
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_get_hostname(char *buffer, size_t size);

/*
 * util_get_kernel_version - Get kernel version
 * 
 * @param buffer: Output buffer
 * @param size: Buffer size
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_get_kernel_version(char *buffer, size_t size);

/*
 * util_get_uptime - Get system uptime in seconds
 * 
 * @param uptime: Output uptime
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_get_uptime(time_t *uptime);

/*
 * util_get_load_avg - Get load averages
 * 
 * @param load1: 1-minute load average
 * @param load5: 5-minute load average
 * @param load15: 15-minute load average
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t util_get_load_avg(double *load1, double *load5, double *load15);

/* ============================================================
 * PROCESS UTILITIES
 * ============================================================ */

/*
 * util_process_exists - Check if process exists
 * 
 * @param pid: Process ID
 * 
 * Returns: 1 if exists, 0 if not
 */
int util_process_exists(pid_t pid);

/*
 * util_process_running - Check if process is running
 * 
 * @param name: Process name
 * 
 * Returns: 1 if running, 0 if not
 */
int util_process_running(const char *name);

/*
 * util_get_process_count - Get total number of processes
 * 
 * Returns: Number of processes or -1 on error
 */
int util_get_process_count(void);

#endif /* SYSSEC_UTILS_H */
