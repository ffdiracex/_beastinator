/*
 * alert.h - Alert system for SYSSEC tools
 * 
 * Provides email and command-based alerting.
 * 
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_ALERT_H
#define SYSSEC_ALERT_H

#include "syssec.h"

/* ============================================================
 * ALERT FUNCTIONS
 * ============================================================ */

/*
 * alert_send_email - Send email alert
 * 
 * @param to: Recipient email address
 * @param subject: Email subject
 * @param body: Email body
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t alert_send_email(const char *to, const char *subject, const char *body);

/*
 * alert_run_command - Execute alert command
 * 
 * @param command: Command to run
 * @param message: Message to pass to command
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t alert_run_command(const char *command, const char *message);

/*
 * alert_send - Send alert via configured method
 * 
 * @param email: Email address (can be NULL)
 * @param command: Alert command (can be NULL)
 * @param subject: Alert subject
 * @param message: Alert message
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t alert_send(const char *email, const char *command,
                          const char *subject, const char *message);

/*
 * alert_should_alert - Check if alert should be sent
 * 
 * @param state_file: State file name
 * @param check_name: Check name for deduplication
 * @param cooldown_hours: Hours to wait between alerts
 * 
 * Returns: 1 if alert should be sent, 0 otherwise
 */
int alert_should_alert(const char *state_file, const char *check_name, 
                       int cooldown_hours);

/*
 * alert_reset - Reset alert state
 * 
 * @param state_file: State file name
 * @param check_name: Check name
 */
void alert_reset(const char *state_file, const char *check_name);

/*
 * alert_format_message - Format alert message with system info
 * 
 * @param buffer: Output buffer
 * @param size: Buffer size
 * @param message: Original message
 */
void alert_format_message(char *buffer, size_t size, const char *message);

#endif /* SYSSEC_ALERT_H */
