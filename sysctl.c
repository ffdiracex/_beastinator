/*
 * sysctl.c - Kernel Control Interface for FreeBSD
 * 
 * Provides a complete interface to the sysctl(3) system,
 * including module information, process data, and system statistics.
 * 
 * Compile: cc -Wall -Wextra -O2 -c sysctl.c -o sysctl.o
 */

#define __BSD_VISIBLE 1
#define _WANT_FREEBSD11_STAT 1
#define _WANT_FREEBSD11_KINFO 1

#include "sysctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#ifndef CTL_MAXNAME
#define CTL_MAXNAME 32
#endif

/* ============================================================
 * INTERNAL: Error to String
 * ============================================================ */

static const char* sysctl_error_string(sysctl_error_t err) {
    switch (err) {
        case SYSCTL_OK:                 return "Success";
        case SYSCTL_ERR_NO_MEMORY:      return "Out of memory";
        case SYSCTL_ERR_PERMISSION:     return "Permission denied";
        case SYSCTL_ERR_NOT_FOUND:      return "Not found";
        case SYSCTL_ERR_BUF_TOO_SMALL:  return "Buffer too small";
        case SYSCTL_ERR_INVALID:        return "Invalid argument";
        case SYSCTL_ERR_IO:             return "I/O error";
        case SYSCTL_ERR_NOT_IMPLEMENTED: return "Not implemented";
        case SYSCTL_ERR_BAD_TYPE:       return "Bad type";
        default:                        return "Unknown error";
    }
}

/* ============================================================
 * INTERNAL: MIB to Name
 * ============================================================ */

static sysctl_error_t sysctl_mib_to_name(const int *mib, int mib_len, 
                                         char *buffer, size_t *size) {
    if (!mib || !buffer || !size) {
        return SYSCTL_ERR_INVALID;
    }
    
    if (sysctl(mib, mib_len, buffer, size, NULL, 0) < 0) {
        if (errno == ENOENT) return SYSCTL_ERR_NOT_FOUND;
        if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
        return SYSCTL_ERR_IO;
    }
    
    return SYSCTL_OK;
}

/* ============================================================
 * INTERNAL: Name to MIB
 * ============================================================ */

static sysctl_error_t sysctl_name_to_mib(const char *name, int *mib, int *mib_len) {
    size_t len = CTL_MAXNAME;
    
    if (!name || !mib || !mib_len) {
        return SYSCTL_ERR_INVALID;
    }
    
    if (sysctlnametomib(name, mib, &len) < 0) {
        if (errno == ENOENT) return SYSCTL_ERR_NOT_FOUND;
        if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
        return SYSCTL_ERR_INVALID;
    }
    
    *mib_len = (int)len;
    return SYSCTL_OK;
}

/* ============================================================
 * INTERNAL: Detect OID Type
 * ============================================================ */

static sysctl_error_t sysctl_detect_type(const int *mib, int mib_len,
                                         sysctl_type_t *type,
                                         int *kind,
                                         char *format, size_t format_size) {
    int type_mib[CTL_MAXNAME + 2];
    int val = 0;
    size_t len = sizeof(int);
    char fmt[64];
    size_t fmt_len = sizeof(fmt);
    int ret;
    
    if (!mib || !type) {
        return SYSCTL_ERR_INVALID;
    }
    
    /* Get OID kind (flags) */
    memcpy(type_mib, mib, mib_len * sizeof(int));
    type_mib[mib_len] = CTLTYPE;
    
    if (sysctl(type_mib, mib_len + 1, &val, &len, NULL, 0) < 0) {
        *type = SYSCTL_TYPE_UNKNOWN;
        if (kind) *kind = 0;
        return SYSCTL_ERR_IO;
    }
    
    if (kind) *kind = val;
    
    /* Determine type from CTLTYPE mask */
    switch (val & CTLTYPE) {
        case CTLTYPE_INT:
            *type = SYSCTL_TYPE_INT;
            break;
        case CTLTYPE_LONG:
            *type = SYSCTL_TYPE_LONG;
            break;
        case CTLTYPE_STRING:
            *type = SYSCTL_TYPE_STRING;
            break;
        case CTLTYPE_UINT:
            *type = SYSCTL_TYPE_UINT;
            break;
        case CTLTYPE_ULONG:
            *type = SYSCTL_TYPE_ULONG;
            break;
        case CTLTYPE_OPAQUE:
            *type = SYSCTL_TYPE_OPAQUE;
            break;
        case CTLTYPE_NODE:
            *type = SYSCTL_TYPE_NODE;
            break;
        default:
            *type = SYSCTL_TYPE_UNKNOWN;
    }
    
    /* Get format string */
    if (format) {
        memcpy(type_mib, mib, mib_len * sizeof(int));
        type_mib[mib_len] = CTLFORMAT;
        fmt_len = sizeof(fmt);
        
        ret = sysctl(type_mib, mib_len + 1, fmt, &fmt_len, NULL, 0);
        if (ret == 0 && fmt_len > 0) {
            strncpy(format, fmt, format_size - 1);
            format[format_size - 1] = '\0';
        } else {
            format[0] = '\0';
        }
    }
    
    return SYSCTL_OK;
}

/* ============================================================
 * PUBLIC: Initialization
 * ============================================================ */

sysctl_error_t sysctl_init(sysctl_state_t *state) {
    if (!state) {
        return SYSCTL_ERR_INVALID;
    }
    
    memset(state, 0, sizeof(sysctl_state_t));
    state->root_mib_len = 0;
    state->num_nodes = 0;
    state->nodes = NULL;
    state->cached = 0;
    
    return SYSCTL_OK;
}

void sysctl_cleanup(sysctl_state_t *state) {
    if (!state) {
        return;
    }
    
    if (state->nodes) {
        for (int i = 0; i < state->num_nodes; i++) {
            if (state->nodes[i].type == SYSCTL_TYPE_STRING && 
                state->nodes[i].value.string_val) {
                free(state->nodes[i].value.string_val);
            }
            if (state->nodes[i].data) {
                free(state->nodes[i].data);
            }
        }
        free(state->nodes);
        state->nodes = NULL;
    }
    
    state->num_nodes = 0;
    state->root_mib_len = 0;
    state->cached = 0;
}

/* ============================================================
 * PUBLIC: Get Value by Name
 * ============================================================ */

sysctl_error_t sysctl_get_value(const char *name, sysctl_value_t *value, sysctl_type_t *type) {
    int mib[CTL_MAXNAME];
    int mib_len;
    sysctl_error_t err;
    size_t size;
    char *str_buffer;
    int int_val;
    long long_val;
    unsigned int uint_val;
    unsigned long ulong_val;
    
    if (!name || !value) {
        return SYSCTL_ERR_INVALID;
    }
    
    /* Convert name to MIB */
    err = sysctl_name_to_mib(name, mib, &mib_len);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    /* Get type */
    sysctl_type_t val_type;
    err = sysctl_detect_type(mib, mib_len, &val_type, NULL, NULL, 0);
    if (err != SYSCTL_OK && err != SYSCTL_ERR_IO) {
        return err;
    }
    
    if (type) {
        *type = val_type;
    }
    
    switch (val_type) {
        case SYSCTL_TYPE_INT:
            size = sizeof(int);
            if (sysctl(mib, mib_len, &int_val, &size, NULL, 0) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            value->int_val = int_val;
            break;
            
        case SYSCTL_TYPE_LONG:
            size = sizeof(long);
            if (sysctl(mib, mib_len, &long_val, &size, NULL, 0) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            value->long_val = long_val;
            break;
            
        case SYSCTL_TYPE_UINT:
            size = sizeof(unsigned int);
            if (sysctl(mib, mib_len, &uint_val, &size, NULL, 0) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            value->uint_val = uint_val;
            break;
            
        case SYSCTL_TYPE_ULONG:
            size = sizeof(unsigned long);
            if (sysctl(mib, mib_len, &ulong_val, &size, NULL, 0) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            value->ulong_val = ulong_val;
            break;
            
        case SYSCTL_TYPE_STRING:
            /* Get size first */
            size = 0;
            if (sysctl(mib, mib_len, NULL, &size, NULL, 0) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            
            if (size == 0) {
                value->string_val = strdup("");
                if (!value->string_val) {
                    return SYSCTL_ERR_NO_MEMORY;
                }
                break;
            }
            
            str_buffer = malloc(size + 1);
            if (!str_buffer) {
                return SYSCTL_ERR_NO_MEMORY;
            }
            
            if (sysctl(mib, mib_len, str_buffer, &size, NULL, 0) < 0) {
                free(str_buffer);
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            
            str_buffer[size] = '\0';
            value->string_val = str_buffer;
            break;
            
        case SYSCTL_TYPE_OPAQUE:
            /* Get size first */
            size = 0;
            if (sysctl(mib, mib_len, NULL, &size, NULL, 0) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            
            if (size == 0) {
                value->opaque_val = NULL;
                break;
            }
            
            str_buffer = malloc(size);
            if (!str_buffer) {
                return SYSCTL_ERR_NO_MEMORY;
            }
            
            if (sysctl(mib, mib_len, str_buffer, &size, NULL, 0) < 0) {
                free(str_buffer);
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            
            value->opaque_val = str_buffer;
            break;
            
        case SYSCTL_TYPE_NODE:
        default:
            return SYSCTL_ERR_NOT_IMPLEMENTED;
    }
    
    return SYSCTL_OK;
}

/* ============================================================
 * PUBLIC: Set Value by Name
 * ============================================================ */

sysctl_error_t sysctl_set_value(const char *name, sysctl_value_t *value, sysctl_type_t *type) {
    int mib[CTL_MAXNAME];
    int mib_len;
    sysctl_error_t err;
    sysctl_type_t val_type;
    size_t size;
    
    if (!name || !value) {
        return SYSCTL_ERR_INVALID;
    }
    
    /* Convert name to MIB */
    err = sysctl_name_to_mib(name, mib, &mib_len);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    /* Determine type */
    if (type) {
        val_type = *type;
    } else {
        err = sysctl_detect_type(mib, mib_len, &val_type, NULL, NULL, 0);
        if (err != SYSCTL_OK) {
            return err;
        }
    }
    
    switch (val_type) {
        case SYSCTL_TYPE_INT:
            size = sizeof(int);
            if (sysctl(mib, mib_len, NULL, 0, &value->int_val, size) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            break;
            
        case SYSCTL_TYPE_LONG:
            size = sizeof(long);
            if (sysctl(mib, mib_len, NULL, 0, &value->long_val, size) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            break;
            
        case SYSCTL_TYPE_UINT:
            size = sizeof(unsigned int);
            if (sysctl(mib, mib_len, NULL, 0, &value->uint_val, size) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            break;
            
        case SYSCTL_TYPE_ULONG:
            size = sizeof(unsigned long);
            if (sysctl(mib, mib_len, NULL, 0, &value->ulong_val, size) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            break;
            
        case SYSCTL_TYPE_STRING:
            if (!value->string_val) {
                return SYSCTL_ERR_INVALID;
            }
            size = strlen(value->string_val) + 1;
            if (sysctl(mib, mib_len, NULL, 0, value->string_val, size) < 0) {
                if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
                return SYSCTL_ERR_IO;
            }
            break;
            
        default:
            return SYSCTL_ERR_NOT_IMPLEMENTED;
    }
    
    return SYSCTL_OK;
}

/* ============================================================
 * PUBLIC: Get Modules (Kernel Modules) - FIXED
 * ============================================================ */

sysctl_error_t sysctl_get_modules(module_info_t **modules, int *count) {
    FILE *fp;
    char line[512];
    module_info_t *result = NULL;
    int num = 0;
    int capacity = 128;
    int id, refs;
    size_t size;
    char name[256];
    char addr[32];
    char *p;
    
    if (!modules || !count) {
        return SYSCTL_ERR_INVALID;
    }
    
    *modules = NULL;
    *count = 0;
    
    /* First try using kldstat(2) directly */
    int fileid = kldfirst(0);
    if (fileid > 0) {
        result = malloc(capacity * sizeof(module_info_t));
        if (!result) {
            return SYSCTL_ERR_NO_MEMORY;
        }
        
        while (fileid > 0 && num < capacity) {
            struct kld_file_stat stat;
            if (kldstat(fileid, &stat) == 0) {
                strncpy(result[num].name, stat.name, sizeof(result[num].name) - 1);
                result[num].name[sizeof(result[num].name) - 1] = '\0';
                result[num].id = stat.id;
                result[num].size = stat.size;
                result[num].refs = stat.refs;
                result[num].version = 0;
                result[num].is_loaded = 1;
                
                /* Check if module file exists in filesystem */
                char path[512];
                snprintf(path, sizeof(path), "/boot/kernel/%s.ko", stat.name);
                if (access(path, F_OK) == 0) {
                    result[num].is_in_filesystem = 1;
                } else {
                    snprintf(path, sizeof(path), "/boot/modules/%s.ko", stat.name);
                    if (access(path, F_OK) == 0) {
                        result[num].is_in_filesystem = 1;
                    } else {
                        result[num].is_in_filesystem = 0;
                    }
                }
                num++;
            }
            fileid = kldnext(fileid);
        }
        
        *modules = result;
        *count = num;
        return SYSCTL_OK;
    }
    
    /* Fallback: use kldstat command */
    fp = popen("kldstat 2>/dev/null", "r");
    if (!fp) {
        return SYSCTL_ERR_IO;
    }
    
    result = malloc(capacity * sizeof(module_info_t));
    if (!result) {
        pclose(fp);
        return SYSCTL_ERR_NO_MEMORY;
    }
    
    /* Skip header line */
    fgets(line, sizeof(line), fp);
    
    while (fgets(line, sizeof(line), fp) && num < capacity) {
        /* Remove newline */
        p = strchr(line, '\n');
        if (p) *p = '\0';
        
        /* Parse: Id Refs Address Size Name */
        /* Format: "1 1 0xffffffff80200000 0x12345678 kernel" */
        if (sscanf(line, "%d %d %s %zx %[^ ]", &id, &refs, addr, &size, name) == 5) {
            strncpy(result[num].name, name, sizeof(result[num].name) - 1);
            result[num].name[sizeof(result[num].name) - 1] = '\0';
            result[num].id = id;
            result[num].size = size;
            result[num].refs = refs;
            result[num].version = 0;
            result[num].is_loaded = 1;
            
            /* Check if module file exists */
            char path[512];
            snprintf(path, sizeof(path), "/boot/kernel/%s.ko", name);
            if (access(path, F_OK) == 0) {
                result[num].is_in_filesystem = 1;
            } else {
                snprintf(path, sizeof(path), "/boot/modules/%s.ko", name);
                if (access(path, F_OK) == 0) {
                    result[num].is_in_filesystem = 1;
                } else {
                    result[num].is_in_filesystem = 0;
                }
            }
            num++;
        }
    }
    
    pclose(fp);
    
    *modules = result;
    *count = num;
    
    return SYSCTL_OK;
}

/* ============================================================
 * PUBLIC: Get Processes
 * ============================================================ */

sysctl_error_t sysctl_get_processes(struct kinfo_proc **proc_list, size_t *count) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len = 0;
    
    if (!proc_list || !count) {
        return SYSCTL_ERR_INVALID;
    }
    
    *proc_list = NULL;
    *count = 0;
    
    /* Get required buffer size */
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        return SYSCTL_ERR_IO;
    }
    
    if (len == 0) {
        return SYSCTL_OK;
    }
    
    *proc_list = malloc(len);
    if (!*proc_list) {
        return SYSCTL_ERR_NO_MEMORY;
    }
    
    if (sysctl(mib, 4, *proc_list, &len, NULL, 0) < 0) {
        free(*proc_list);
        *proc_list = NULL;
        return SYSCTL_ERR_IO;
    }
    
    *count = len / sizeof(struct kinfo_proc);
    return SYSCTL_OK;
}

/* ============================================================
 * PUBLIC: Convenience Getters
 * ============================================================ */

sysctl_error_t sysctl_get_hostname(char *buffer, size_t size) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!buffer || size == 0) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("kern.hostname", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    strncpy(buffer, value.string_val, size - 1);
    buffer[size - 1] = '\0';
    free(value.string_val);
    
    return SYSCTL_OK;
}

sysctl_error_t sysctl_set_hostname(const char *hostname) {
    sysctl_value_t value;
    
    if (!hostname) {
        return SYSCTL_ERR_INVALID;
    }
    
    value.string_val = (char *)hostname;
    return sysctl_set_value("kern.hostname", &value, SYSCTL_TYPE_STRING);
}

sysctl_error_t sysctl_get_kernel_version(char *buffer, size_t size) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!buffer || size == 0) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("kern.version", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    strncpy(buffer, value.string_val, size - 1);
    buffer[size - 1] = '\0';
    free(value.string_val);
    
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_os_release(char *buffer, size_t size) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!buffer || size == 0) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("kern.osrelease", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    strncpy(buffer, value.string_val, size - 1);
    buffer[size - 1] = '\0';
    free(value.string_val);
    
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_cpu_model(char *buffer, size_t size) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!buffer || size == 0) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("hw.model", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    strncpy(buffer, value.string_val, size - 1);
    buffer[size - 1] = '\0';
    free(value.string_val);
    
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_num_cpus(int *count) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!count) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("hw.ncpu", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    *count = value.int_val;
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_phys_memory(long *size) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!size) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("hw.physmem", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    *size = (long)value.ulong_val;
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_boot_time(long *boot_time) {
    struct timeval tv;
    size_t len = sizeof(tv);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    
    if (!boot_time) {
        return SYSCTL_ERR_INVALID;
    }
    
    if (sysctl(mib, 2, &tv, &len, NULL, 0) < 0) {
        if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
        return SYSCTL_ERR_IO;
    }
    
    *boot_time = tv.tv_sec;
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_load_avg(double *load1, double *load5, double *load15) {
    struct loadavg load;
    size_t len = sizeof(load);
    int mib[2] = {CTL_VM, VM_LOADAVG};
    
    if (sysctl(mib, 2, &load, &len, NULL, 0) < 0) {
        if (errno == EACCES) return SYSCTL_ERR_PERMISSION;
        return SYSCTL_ERR_IO;
    }
    
    if (load1) *load1 = (double)load.ldavg[0] / load.fscale;
    if (load5) *load5 = (double)load.ldavg[1] / load.fscale;
    if (load15) *load15 = (double)load.ldavg[2] / load.fscale;
    
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_open_files(int *count) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!count) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("kern.openfiles", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    *count = value.int_val;
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_max_files(int *max) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!max) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("kern.maxfiles", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    *max = value.int_val;
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_securelevel(int *level) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!level) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("kern.securelevel", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    *level = value.int_val;
    return SYSCTL_OK;
}

sysctl_error_t sysctl_get_ip_forwarding(int *enabled) {
    sysctl_value_t value;
    sysctl_error_t err;
    
    if (!enabled) {
        return SYSCTL_ERR_INVALID;
    }
    
    err = sysctl_get_value("net.inet.ip.forwarding", &value, NULL);
    if (err != SYSCTL_OK) {
        return err;
    }
    
    *enabled = value.int_val;
    return SYSCTL_OK;
}

/* ============================================================
 * PUBLIC: Free Functions
 * ============================================================ */

void sysctl_free_modules(module_info_t *modules, int count) {
    (void)count;
    if (modules) {
        free(modules);
    }
}

void sysctl_free_processes(struct kinfo_proc *proc_list, size_t count) {
    (void)count;
    if (proc_list) {
        free(proc_list);
    }
}

void sysctl_free_nodes(sysctl_node_t *nodes, int count) {
    if (!nodes) {
        return;
    }
    
    for (int i = 0; i < count; i++) {
        if (nodes[i].type == SYSCTL_TYPE_STRING && nodes[i].value.string_val) {
            free(nodes[i].value.string_val);
        }
        if (nodes[i].data) {
            free(nodes[i].data);
        }
    }
    
    free(nodes);
}
