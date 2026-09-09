/*
 * scheduler.h - Cron scheduler for SYSSEC tools
 * 
 * Provides automated scheduling via cron.
 * 
 * Copyright (c) 2026-2027 SYSSEC Project
 */

#ifndef SYSSEC_SCHEDULER_H
#define SYSSEC_SCHEDULER_H

#include "syssec.h"

/* ============================================================
 * SCHEDULER FUNCTIONS
 * ============================================================ */

/*
 * scheduler_install - Install cron job
 * 
 * @param schedule: Cron schedule string (e.g., "0 2 * * *")
 * @param command: Command to run
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scheduler_install(const char *schedule, const char *command);

/*
 * scheduler_remove - Remove cron job
 * 
 * @param command: Command to remove
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scheduler_remove(const char *command);

/*
 * scheduler_status - Check if cron job is installed
 * 
 * @param command: Command to check
 * 
 * Returns: 1 if installed, 0 if not
 */
int scheduler_status(const char *command);

/*
 * scheduler_list - List all SYSSEC cron jobs
 */
void scheduler_list(void);

/*
 * scheduler_validate_cron - Validate cron schedule string
 * 
 * @param schedule: Cron schedule string
 * 
 * Returns: 1 if valid, 0 if invalid
 */
int scheduler_validate_cron(const char *schedule);

/*
 * scheduler_install_daily - Install daily scan
 * 
 * @param command: Command to run
 * @param hour: Hour (0-23)
 * @param minute: Minute (0-59)
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scheduler_install_daily(const char *command, int hour, int minute);

/*
 * scheduler_install_hourly - Install hourly scan
 * 
 * @param command: Command to run
 * @param minute: Minute (0-59)
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scheduler_install_hourly(const char *command, int minute);

#endif /* SYSSEC_SCHEDULER_H */
