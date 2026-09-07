/*
 * config.h - Configuration system for SYSSEC tools
 * 
 * Provides configuration file parsing and management.
 * 
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_CONFIG_H
#define SYSSEC_CONFIG_H

#include "syssec.h"

/* ============================================================
 * CONFIGURATION STRUCTURE
 * ============================================================ */

typedef struct {
    /* Output settings */
    int use_colors;
    int verbose;
    int json_output;
    int html_output;
    
    /* Logging */
    char log_dir[MAX_PATH];
    char log_file[MAX_NAME];
    int log_level;
    
    /* Alerts */
    int enable_alerts;
    char alert_email[MAX_STRING];
    char alert_command[MAX_STRING];
    int alert_cooldown_hours;
    
    /* Reporting */
    char report_dir[MAX_PATH];
    int save_reports;
    int report_retention_days;
    
    /* Scheduling */
    int schedule_enabled;
    char schedule_cron[MAX_STRING];
    
    /* Thresholds (percent) */
    int cpu_threshold;
    int memory_threshold;
    int disk_threshold;
    int temperature_threshold;
    int load_threshold;
    
    /* Checks to run */
    int check_system;
    int check_users;
    int check_security;
    int check_health;
    int check_updates;
    int check_misc;
    
    /* Exclusions */
    char exclude_users[MAX_STRING];
    char exclude_paths[MAX_STRING];
    char exclude_services[MAX_STRING];
    
    /* Network */
    char dns_servers[MAX_STRING];
    char ntp_servers[MAX_STRING];
    
    /* Internal */
    char config_path[MAX_PATH];
    int initialized;
} syssec_config_t;

/* ============================================================
 * FUNCTION PROTOTYPES
 * ============================================================ */

/*
 * syssec_config_init - Initialize configuration with defaults
 * 
 * @param config: Pointer to config structure
 */
void syssec_config_init(syssec_config_t *config);

/*
 * syssec_config_load - Load configuration from file
 * 
 * @param config: Pointer to config structure
 * @param path: Path to configuration file
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t syssec_config_load(syssec_config_t *config, const char *path);

/*
 * syssec_config_save - Save configuration to file
 * 
 * @param config: Pointer to config structure
 * @param path: Path to configuration file
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t syssec_config_save(syssec_config_t *config, const char *path);

/*
 * syssec_config_print - Print configuration
 * 
 * @param config: Pointer to config structure
 */
void syssec_config_print(syssec_config_t *config);

/*
 * syssec_config_default_path - Get default config path
 * 
 * @param buffer: Output buffer
 * @param size: Buffer size
 */
void syssec_config_default_path(char *buffer, size_t size);

#endif /* SYSSEC_CONFIG_H */
