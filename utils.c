/*
 * utils.c - Utility functions for SYSSEC tools
 * 
 * Provides common helper functions used across the project.
 * 
 * Compile: cc -Wall -Wextra -O2 -c utils.c -o utils.o
 */

#define __BSD_VISIBLE 1

#include "syssec.h"
#include "utils.h"
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>

/* ============================================================
 * STRING UTILITIES
 * ============================================================ */

char* util_trim(char *str) {
    char *end;
    
    if (!str) return NULL;
    
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == 0) return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    /* Write new null terminator */
    *(end + 1) = '\0';
    return str;
}

char* util_strdup(const char *str) {
    char *result;
    size_t len;
    
    if (!str) return NULL;
    
    len = strlen(str) + 1;
    result = malloc(len);
    if (!result) return NULL;
    
    memcpy(result, str, len);
    return result;
}

syssec_error_t util_join_path(char *dest, size_t size, const char *parts, ...) {
    va_list args;
    const char *part;
    size_t written = 0;
    
    if (!dest || size == 0) {
        return SYSSEC_ERR_INVALID;
    }
    
    dest[0] = '\0';
    va_start(args, parts);
    part = parts;
    
    while (part != NULL) {
        size_t len = strlen(part);
        
        /* Add separator if not first part and no trailing slash */
        if (written > 0 && dest[written - 1] != '/' && part[0] != '/') {
            if (written + 1 >= size) break;
            dest[written++] = '/';
            dest[written] = '\0';
        }
        
        /* Copy part */
        if (written + len >= size) break;
        strcpy(dest + written, part);
        written += len;
        
        part = va_arg(args, const char*);
    }
    
    va_end(args);
    return SYSSEC_OK;
}

void util_safe_filename(const char *src, char *dest, size_t size) {
    const char *allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
    size_t i, j = 0;
    
    if (!src || !dest || size == 0) {
        if (dest && size > 0) dest[0] = '\0';
        return;
    }
    
    for (i = 0; src[i] && j < size - 1; i++) {
        if (strchr(allowed, src[i])) {
            dest[j++] = src[i];
        } else {
            dest[j++] = '_';
        }
    }
    dest[j] = '\0';
}

/* ============================================================
 * FILE UTILITIES
 * ============================================================ */

int util_file_exists(const char *path) {
    struct stat st;
    if (!path) return 0;
    return stat(path, &st) == 0;
}

int util_dir_exists(const char *path) {
    struct stat st;
    if (!path) return 0;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

syssec_error_t util_create_dir(const char *path, mode_t mode) {
    char *path_copy;
    char *p;
    
    if (!path) return SYSSEC_ERR_INVALID;
    
    path_copy = util_strdup(path);
    if (!path_copy) return SYSSEC_ERR_NO_MEMORY;
    
    /* Recursively create directories */
    p = path_copy;
    while (*p) {
        if (*p == '/' && p != path_copy) {
            *p = '\0';
            mkdir(path_copy, mode);
            *p = '/';
        }
        p++;
    }
    mkdir(path_copy, mode);
    
    free(path_copy);
    return SYSSEC_OK;
}

syssec_error_t util_read_file(const char *path, char **data, size_t *size) {
    FILE *fp;
    long file_size;
    char *buffer;
    
    if (!path || !data || !size) {
        return SYSSEC_ERR_INVALID;
    }
    
    fp = fopen(path, "r");
    if (!fp) {
        return SYSSEC_ERR_IO;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size < 0) {
        fclose(fp);
        return SYSSEC_ERR_IO;
    }
    
    buffer = malloc(file_size + 1);
    if (!buffer) {
        fclose(fp);
        return SYSSEC_ERR_NO_MEMORY;
    }
    
    if (fread(buffer, 1, file_size, fp) != (size_t)file_size) {
        free(buffer);
        fclose(fp);
        return SYSSEC_ERR_IO;
    }
    
    buffer[file_size] = '\0';
    
    fclose(fp);
    *data = buffer;
    *size = file_size;
    
    return SYSSEC_OK;
}

syssec_error_t util_write_file(const char *path, const char *data, size_t size) {
    FILE *fp;
    
    if (!path || !data) {
        return SYSSEC_ERR_INVALID;
    }
    
    if (size == 0) {
        size = strlen(data);
    }
    
    fp = fopen(path, "w");
    if (!fp) {
        return SYSSEC_ERR_IO;
    }
    
    if (fwrite(data, 1, size, fp) != size) {
        fclose(fp);
        return SYSSEC_ERR_IO;
    }
    
    fclose(fp);
    return SYSSEC_OK;
}

/* ============================================================
 * SYSTEM UTILITIES
 * ============================================================ */

syssec_error_t util_get_hostname(char *buffer, size_t size) {
    size_t len = size;
    
    if (!buffer || size == 0) {
        return SYSSEC_ERR_INVALID;
    }
    
    if (sysctlbyname("kern.hostname", buffer, &len, NULL, 0) < 0) {
        return SYSSEC_ERR_IO;
    }
    
    buffer[size - 1] = '\0';
    return SYSSEC_OK;
}

syssec_error_t util_get_kernel_version(char *buffer, size_t size) {
    size_t len = size;
    
    if (!buffer || size == 0) {
        return SYSSEC_ERR_INVALID;
    }
    
    if (sysctlbyname("kern.version", buffer, &len, NULL, 0) < 0) {
        return SYSSEC_ERR_IO;
    }
    
    buffer[size - 1] = '\0';
    return SYSSEC_OK;
}

syssec_error_t util_get_uptime(time_t *uptime) {
    struct timeval boottime;
    size_t len = sizeof(boottime);
    time_t now;
    
    if (!uptime) {
        return SYSSEC_ERR_INVALID;
    }
    
    if (sysctlbyname("kern.boottime", &boottime, &len, NULL, 0) < 0) {
        return SYSSEC_ERR_IO;
    }
    
    now = time(NULL);
    *uptime = now - boottime.tv_sec;
    
    return SYSSEC_OK;
}

syssec_error_t util_get_load_avg(double *load1, double *load5, double *load15) {
    struct loadavg load;
    size_t len = sizeof(load);
    int mib[2] = {CTL_VM, VM_LOADAVG};
    
    if (sysctl(mib, 2, &load, &len, NULL, 0) < 0) {
        return SYSSEC_ERR_IO;
    }
    
    if (load1) *load1 = (double)load.ldavg[0] / load.fscale;
    if (load5) *load5 = (double)load.ldavg[1] / load.fscale;
    if (load15) *load15 = (double)load.ldavg[2] / load.fscale;
    
    return SYSSEC_OK;
}

/* ============================================================
 * PROCESS UTILITIES
 * ============================================================ */

int util_process_exists(pid_t pid) {
    return kill(pid, 0) == 0;
}

int util_process_running(const char *name) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "pgrep -x %s > /dev/null 2>&1", name);
    return system(cmd) == 0;
}

int util_get_process_count(void) {
    struct kinfo_proc *proc_list = NULL;
    size_t len = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int count;
    
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        return -1;
    }
    
    proc_list = malloc(len);
    if (!proc_list) {
        return -1;
    }
    
    if (sysctl(mib, 4, proc_list, &len, NULL, 0) < 0) {
        free(proc_list);
        return -1;
    }
    
    count = len / sizeof(struct kinfo_proc);
    free(proc_list);
    
    return count;
}

/* ============================================================
 * STRING LIST FUNCTIONS
 * ============================================================ */

int util_string_list_contains(const char *list, const char *item) {
    char *list_copy;
    char *token;
    char *saveptr;
    int found = 0;
    
    if (!list || !item || list[0] == '\0') {
        return 0;
    }
    
    list_copy = strdup(list);
    if (!list_copy) {
        return 0;
    }
    
    token = strtok_r(list_copy, ",", &saveptr);
    while (token) {
        /* Trim whitespace */
        while (*token == ' ' || *token == '\t') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        
        if (strcmp(token, item) == 0) {
            found = 1;
            break;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    free(list_copy);
    return found;
}
