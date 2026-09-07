/*
 * sysctl.h - Kernel Control Interface for FreeBSD
 * 
 * Provides a complete interface to the sysctl(3) system,
 * including module information, process data, and system statistics.
 * 
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_SYSCTL_H
#define SYSSEC_SYSCTL_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    SYSCTL_OK               = 0,
    SYSCTL_ERR_NO_MEMORY    = -1,
    SYSCTL_ERR_PERMISSION   = -2,
    SYSCTL_ERR_NOT_FOUND    = -3,
    SYSCTL_ERR_BUF_TOO_SMALL = -4,
    SYSCTL_ERR_INVALID      = -5,
    SYSCTL_ERR_IO           = -6,
    SYSCTL_ERR_NOT_IMPLEMENTED = -7,
    SYSCTL_ERR_BAD_TYPE     = -8,
    SYSCTL_ERR_CACHE_MISS   = -9
} sysctl_error_t;

/* ============================================================
 * TYPES
 * ============================================================ */

typedef enum {
    SYSCTL_TYPE_INT,
    SYSCTL_TYPE_LONG,
    SYSCTL_TYPE_STRING,
    SYSCTL_TYPE_UINT,
    SYSCTL_TYPE_ULONG,
    SYSCTL_TYPE_OPAQUE,
    SYSCTL_TYPE_NODE,
    SYSCTL_TYPE_UNKNOWN
} sysctl_type_t;

typedef union sysctl_value {
    int         int_val;
    long        long_val;
    unsigned int uint_val;
    unsigned long ulong_val;
    char        *string_val;
    void        *opaque_val;
} sysctl_value_t;

typedef struct sysctl_node {
    char            name[256];
    char            full_path[512];
    sysctl_type_t   type;
    int             mib[CTL_MAXNAME];
    int             mib_len;
    void           *data;
    size_t          data_len;
    sysctl_value_t  value;
    char            value_str[1024];
    unsigned int    is_node : 1;
    unsigned int    is_readable : 1;
    unsigned int    is_writable : 1;
    unsigned int    is_cache_valid : 1;
} sysctl_node_t;

/* Module information structure */
typedef struct {
    char            name[128];
    int             id;
    size_t          size;
    int             refs;
    int             version;
    int             is_loaded;
    int             is_in_filesystem;
} module_info_t;

/* State structure for sysctl operations */
typedef struct sysctl_state {
    int             num_nodes;
    sysctl_node_t   *nodes;
    int             root_mib[CTL_MAXNAME];
    int             root_mib_len;
    int             cached;
} sysctl_state_t;

/* ============================================================
 * FUNCTION DECLARATIONS
 * ============================================================ */

/* Init / Cleanup */
sysctl_error_t sysctl_init(sysctl_state_t *state);
void sysctl_cleanup(sysctl_state_t *state);

/* Get Values */
sysctl_error_t sysctl_get_value(const char *name, sysctl_value_t *value, sysctl_type_t *type);
sysctl_error_t sysctl_get_value_by_mib(const int *mib, int mib_len,
                                       sysctl_value_t *value, sysctl_type_t *type);

/* Set Values */
sysctl_error_t sysctl_set_value(const char *name, sysctl_value_t *value, sysctl_type_t *type);
sysctl_error_t sysctl_set_value_by_mib(const int *mib, int mib_len,
                                       sysctl_value_t *value, sysctl_type_t *type);

/* Modules (Kernel Modules) */
sysctl_error_t sysctl_get_modules(module_info_t **modules, int *count);
void sysctl_free_modules(module_info_t *modules, int count);

/* Processes */
sysctl_error_t sysctl_get_processes(struct kinfo_proc **proc_list, size_t *count);
void sysctl_free_processes(struct kinfo_proc *proc_list, size_t count);

/* List / Iterate */
sysctl_error_t sysctl_list_nodes(sysctl_state_t *state,
                                 const int *mib, int mib_len,
                                 sysctl_node_t **nodes, int *count);
sysctl_error_t sysctl_list_all(sysctl_state_t *state);
sysctl_error_t sysctl_search(sysctl_state_t *state, const char *pattern,
                             sysctl_node_t **results, int *count);

/* Free */
void sysctl_free_nodes(sysctl_node_t *nodes, int count);

/* ============================================================
 * CONVENIENCE GETTERS
 * ============================================================ */

/* System Information */
sysctl_error_t sysctl_get_hostname(char *buffer, size_t size);
sysctl_error_t sysctl_set_hostname(const char *hostname);
sysctl_error_t sysctl_get_kernel_version(char *buffer, size_t size);
sysctl_error_t sysctl_get_os_release(char *buffer, size_t size);

/* Hardware Information */
sysctl_error_t sysctl_get_cpu_model(char *buffer, size_t size);
sysctl_error_t sysctl_get_num_cpus(int *count);
sysctl_error_t sysctl_get_phys_memory(long *size);

/* System State */
sysctl_error_t sysctl_get_boot_time(long *boot_time);
sysctl_error_t sysctl_get_load_avg(double *load1, double *load5, double *load15);
sysctl_error_t sysctl_get_open_files(int *count);
sysctl_error_t sysctl_get_max_files(int *max);

/* Security */
sysctl_error_t sysctl_get_securelevel(int *level);
sysctl_error_t sysctl_get_ip_forwarding(int *enabled);

/* Internal helper - get value raw */
sysctl_error_t sysctl_get_value_raw(const int *mib, int mib_len,
                                    void *buffer, size_t *size);

#endif /* SYSSEC_SYSCTL_H */
