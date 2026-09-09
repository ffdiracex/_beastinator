/*
 * config.c - Configuration system implementation
 * 
 * Compile: cc -Wall -Wextra -O2 -c config.c -o config.o
 */

#define __BSD_VISIBLE 1

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

/* ============================================================
 * HELPER FUNCTIONS
 * ============================================================ */

static int create_directory(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s 2>/dev/null", path);
    return system(cmd);
}

static char* trim_whitespace(char *str) {
    char *end;
    
    /* Trim leading space */
    while(isspace((unsigned char)*str)) str++;
    
    if(*str == 0) return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    
    /* Write new null terminator */
    *(end+1) = '\0';
    return str;
}

static int parse_bool(const char *str) {
    if (!str) return 0;
    if (strcasecmp(str, "yes") == 0) return 1;
    if (strcasecmp(str, "true") == 0) return 1;
    if (strcasecmp(str, "1") == 0) return 1;
    if (strcasecmp(str, "on") == 0) return 1;
    return 0;
}

static int parse_int(const char *str) {
    if (!str) return 0;
    return atoi(str);
}

static void parse_string(char *dest, const char *src, size_t size) {
    if (dest && src) {
        strncpy(dest, src, size - 1);
        dest[size - 1] = '\0';
    }
}

/* ============================================================
 * CONFIGURATION LOAD
 * ============================================================ */

int syssec_config_load(syssec_config_t *config, const char *path) {
    FILE *fp;
    char line[1024];
    char key[256];
    char value[1024];
    char *equals;
    
    if (!config || !path) {
        return -1;
    }
    
    /* Initialize with defaults first */
    syssec_config_init(config);
    
    fp = fopen(path, "r");
    if (!fp) {
        /* Config file doesn't exist, create default */
        syssec_config_save(config, path);
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') continue;
        
        /* Find equals sign */
        equals = strchr(line, '=');
        if (!equals) continue;
        
        /* Split into key and value */
        *equals = '\0';
        strncpy(key, line, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';
        strncpy(value, equals + 1, sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0';
        
        trim_whitespace(key);
        trim_whitespace(value);
        
        /* Parse configuration keys */
        if (strcmp(key, "use_colors") == 0) {
            config->use_colors = parse_bool(value);
        } else if (strcmp(key, "verbose") == 0) {
            config->verbose = parse_bool(value);
        } else if (strcmp(key, "json_output") == 0) {
            config->json_output = parse_bool(value);
        } else if (strcmp(key, "html_output") == 0) {
            config->html_output = parse_bool(value);
        } else if (strcmp(key, "log_dir") == 0) {
            parse_string(config->log_dir, value, sizeof(config->log_dir));
        } else if (strcmp(key, "log_file") == 0) {
            parse_string(config->log_file, value, sizeof(config->log_file));
        } else if (strcmp(key, "log_level") == 0) {
            config->log_level = parse_int(value);
        } else if (strcmp(key, "enable_alerts") == 0) {
            config->enable_alerts = parse_bool(value);
        } else if (strcmp(key, "alert_email") == 0) {
            parse_string(config->alert_email, value, sizeof(config->alert_email));
        } else if (strcmp(key, "alert_command") == 0) {
            parse_string(config->alert_command, value, sizeof(config->alert_command));
        } else if (strcmp(key, "save_reports") == 0) {
            config->save_reports = parse_bool(value);
        } else if (strcmp(key, "report_retention_days") == 0) {
            config->report_retention_days = parse_int(value);
        } else if (strcmp(key, "schedule_enabled") == 0) {
            config->schedule_enabled = parse_bool(value);
        } else if (strcmp(key, "schedule_cron") == 0) {
            parse_string(config->schedule_cron, value, sizeof(config->schedule_cron));
        } else if (strcmp(key, "cpu_threshold") == 0) {
            config->cpu_threshold = parse_int(value);
        } else if (strcmp(key, "memory_threshold") == 0) {
            config->memory_threshold = parse_int(value);
        } else if (strcmp(key, "disk_threshold") == 0) {
            config->disk_threshold = parse_int(value);
        } else if (strcmp(key, "temperature_threshold") == 0) {
            config->temperature_threshold = parse_int(value);
        } else if (strcmp(key, "load_threshold") == 0) {
            config->load_threshold = parse_int(value);
        } else if (strcmp(key, "check_system") == 0) {
            config->check_system = parse_bool(value);
        } else if (strcmp(key, "check_users") == 0) {
            config->check_users = parse_bool(value);
        } else if (strcmp(key, "check_security") == 0) {
            config->check_security = parse_bool(value);
        } else if (strcmp(key, "check_health") == 0) {
            config->check_health = parse_bool(value);
        } else if (strcmp(key, "check_updates") == 0) {
            config->check_updates = parse_bool(value);
        } else if (strcmp(key, "check_misc") == 0) {
            config->check_misc = parse_bool(value);
        } else if (strcmp(key, "exclude_users") == 0) {
            parse_string(config->exclude_users, value, sizeof(config->exclude_users));
        } else if (strcmp(key, "exclude_paths") == 0) {
            parse_string(config->exclude_paths, value, sizeof(config->exclude_paths));
        } else if (strcmp(key, "exclude_services") == 0) {
            parse_string(config->exclude_services, value, sizeof(config->exclude_services));
        } else if (strcmp(key, "dns_servers") == 0) {
            parse_string(config->dns_servers, value, sizeof(config->dns_servers));
        } else if (strcmp(key, "ntp_servers") == 0) {
            parse_string(config->ntp_servers, value, sizeof(config->ntp_servers));
        }
    }
    
    fclose(fp);
    return 0;
}

/* ============================================================
 * CONFIGURATION SAVE
 * ============================================================ */

int syssec_config_save(syssec_config_t *config, const char *path) {
    FILE *fp;
    char dir_path[512];
    
    if (!config || !path) {
        return -1;
    }
    
    /* Create directory if it doesn't exist */
    strncpy(dir_path, path, sizeof(dir_path) - 1);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        create_directory(dir_path);
    }
    
    fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }
    
    fprintf(fp, "# SYSSEC Configuration File\n");
    fprintf(fp, "# Generated: %s\n\n", ctime(&(time_t){time(NULL)}));
    
    fprintf(fp, "# Output settings\n");
    fprintf(fp, "use_colors = %s\n", config->use_colors ? "yes" : "no");
    fprintf(fp, "verbose = %s\n", config->verbose ? "yes" : "no");
    fprintf(fp, "json_output = %s\n", config->json_output ? "yes" : "no");
    fprintf(fp, "html_output = %s\n\n", config->html_output ? "yes" : "no");
    
    fprintf(fp, "# Logging\n");
    fprintf(fp, "log_dir = %s\n", config->log_dir);
    fprintf(fp, "log_file = %s\n", config->log_file);
    fprintf(fp, "log_level = %d\n\n", config->log_level);
    
    fprintf(fp, "# Alerts\n");
    fprintf(fp, "enable_alerts = %s\n", config->enable_alerts ? "yes" : "no");
    fprintf(fp, "alert_email = %s\n", config->alert_email);
    fprintf(fp, "alert_command = %s\n\n", config->alert_command);
    
    fprintf(fp, "# Reporting\n");
    fprintf(fp, "save_reports = %s\n", config->save_reports ? "yes" : "no");
    fprintf(fp, "report_retention_days = %d\n\n", config->report_retention_days);
    
    fprintf(fp, "# Scheduling\n");
    fprintf(fp, "schedule_enabled = %s\n", config->schedule_enabled ? "yes" : "no");
    fprintf(fp, "schedule_cron = %s\n\n", config->schedule_cron);
    
    fprintf(fp, "# Thresholds (percent)\n");
    fprintf(fp, "cpu_threshold = %d\n", config->cpu_threshold);
    fprintf(fp, "memory_threshold = %d\n", config->memory_threshold);
    fprintf(fp, "disk_threshold = %d\n", config->disk_threshold);
    fprintf(fp, "temperature_threshold = %d\n", config->temperature_threshold);
    fprintf(fp, "load_threshold = %d\n\n", config->load_threshold);
    
    fprintf(fp, "# Checks to run\n");
    fprintf(fp, "check_system = %s\n", config->check_system ? "yes" : "no");
    fprintf(fp, "check_users = %s\n", config->check_users ? "yes" : "no");
    fprintf(fp, "check_security = %s\n", config->check_security ? "yes" : "no");
    fprintf(fp, "check_health = %s\n", config->check_health ? "yes" : "no");
    fprintf(fp, "check_updates = %s\n", config->check_updates ? "yes" : "no");
    fprintf(fp, "check_misc = %s\n\n", config->check_misc ? "yes" : "no");
    
    fprintf(fp, "# Exclusions\n");
    fprintf(fp, "exclude_users = %s\n", config->exclude_users);
    fprintf(fp, "exclude_paths = %s\n", config->exclude_paths);
    fprintf(fp, "exclude_services = %s\n\n", config->exclude_services);
    
    fprintf(fp, "# Network\n");
    fprintf(fp, "dns_servers = %s\n", config->dns_servers);
    fprintf(fp, "ntp_servers = %s\n", config->ntp_servers);
    
    fclose(fp);
    return 0;
}

/* ============================================================
 * CONFIGURATION PRINT
 * ============================================================ */

void syssec_config_print(syssec_config_t *config) {
    if (!config) return;
    
    printf("\n" COLOR_BOLD "=== SYSSEC CONFIGURATION ===\n" COLOR_RESET);
    
    printf("  Output:\n");
    printf("    Colors:      %s\n", config->use_colors ? "yes" : "no");
    printf("    Verbose:     %s\n", config->verbose ? "yes" : "no");
    printf("    JSON:        %s\n", config->json_output ? "yes" : "no");
    printf("    HTML:        %s\n", config->html_output ? "yes" : "no");
    
    printf("\n  Logging:\n");
    printf("    Directory:   %s\n", config->log_dir);
    printf("    File:        %s\n", config->log_file);
    printf("    Level:       %d\n", config->log_level);
    
    printf("\n  Alerts:\n");
    printf("    Enabled:     %s\n", config->enable_alerts ? "yes" : "no");
    printf("    Email:       %s\n", config->alert_email);
    printf("    Command:     %s\n", config->alert_command);
    
    printf("\n  Thresholds:\n");
    printf("    CPU:         %d%%\n", config->cpu_threshold);
    printf("    Memory:      %d%%\n", config->memory_threshold);
    printf("    Disk:        %d%%\n", config->disk_threshold);
    printf("    Temperature: %d°C\n", config->temperature_threshold);
    printf("    Load:        %d%%\n", config->load_threshold);
    
    printf("\n  Checks:\n");
    printf("    System:      %s\n", config->check_system ? "yes" : "no");
    printf("    Users:       %s\n", config->check_users ? "yes" : "no");
    printf("    Security:    %s\n", config->check_security ? "yes" : "no");
    printf("    Health:      %s\n", config->check_health ? "yes" : "no");
    printf("    Updates:     %s\n", config->check_updates ? "yes" : "no");
    printf("    Misc:        %s\n", config->check_misc ? "yes" : "no");
}

/* ============================================================
 * CONFIGURATION FUNCTIONS
 * ============================================================ */

void syssec_config_default_path(char *buffer, size_t size) {
    if (!buffer || size == 0) {
        return;
    }
    
    const char *home = getenv("HOME");
    if (home) {
        snprintf(buffer, size, "%s/.syssec.conf", home);
    } else {
        snprintf(buffer, size, "/etc/syssec/syssec.conf");
    }
}

void syssec_config_init(syssec_config_t *config) {
    if (!config) {
        return;
    }
    
    memset(config, 0, sizeof(syssec_config_t));
    
    /* Default values */
    config->use_colors = 1;
    config->verbose = 0;
    config->json_output = 0;
    config->html_output = 0;
    
    strncpy(config->log_dir, "/var/log/syssec", sizeof(config->log_dir) - 1);
    strncpy(config->log_file, "syssec.log", sizeof(config->log_file) - 1);
    config->log_level = 2;
    
    config->enable_alerts = 0;
    strncpy(config->alert_email, "root@localhost", sizeof(config->alert_email) - 1);
    config->alert_command[0] = '\0';
    config->alert_cooldown_hours = 24;
    
    strncpy(config->report_dir, "/var/log/syssec/reports", sizeof(config->report_dir) - 1);
    config->save_reports = 1;
    config->report_retention_days = 30;
    
    config->schedule_enabled = 0;
    strncpy(config->schedule_cron, "0 2 * * *", sizeof(config->schedule_cron) - 1);
    
    config->cpu_threshold = 80;
    config->memory_threshold = 80;
    config->disk_threshold = 80;
    config->temperature_threshold = 70;
    config->load_threshold = 80;
    
    config->check_system = 1;
    config->check_users = 1;
    config->check_security = 1;
    config->check_health = 1;
    config->check_updates = 1;
    config->check_misc = 1;
    
    config->exclude_users[0] = '\0';
    config->exclude_paths[0] = '\0';
    config->exclude_services[0] = '\0';
    
    strncpy(config->dns_servers, "8.8.8.8,8.8.4.4", sizeof(config->dns_servers) - 1);
    strncpy(config->ntp_servers, "0.freebsd.pool.ntp.org,1.freebsd.pool.ntp.org", 
            sizeof(config->ntp_servers) - 1);
    
    config->initialized = 1;
}
