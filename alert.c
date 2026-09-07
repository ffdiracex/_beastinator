/*
 * alert.c - Alert system for SYSSEC tools
 * 
 * Supports email and command-based alerts.
 * 
 * Compile: cc -Wall -Wextra -O2 -c alert.c -o alert.o
 */

#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ============================================================
 * ALERT FUNCTIONS
 * ============================================================ */

/*
 * alert_send_email - Send email alert
 * Returns: 0 on success, -1 on error
 */
int alert_send_email(const char *to, const char *subject, const char *body) {
    char cmd[2048];
    FILE *fp;
    
    if (!to || !subject || !body) {
        return -1;
    }
    
    /* Check if mail command exists */
    if (system("which mail > /dev/null 2>&1") != 0) {
        return -1;
    }
    
    snprintf(cmd, sizeof(cmd), 
             "echo '%s' | mail -s '%s' '%s' 2>/dev/null",
             body, subject, to);
    
    return system(cmd);
}

/*
 * alert_run_command - Execute alert command
 * Returns: 0 on success, -1 on error
 */
int alert_run_command(const char *command, const char *message) {
    char cmd[2048];
    
    if (!command || !message) {
        return -1;
    }
    
    snprintf(cmd, sizeof(cmd), "%s '%s'", command, message);
    return system(cmd);
}

/*
 * alert_send - Send alert via configured method
 * Returns: 0 on success, -1 on error
 */
int alert_send(const char *email, const char *command, 
               const char *subject, const char *message) {
    int success = 0;
    
    if (email && email[0] != '\0') {
        if (alert_send_email(email, subject, message) == 0) {
            success = 1;
        }
    }
    
    if (command && command[0] != '\0') {
        if (alert_run_command(command, message) == 0) {
            success = 1;
        }
    }
    
    return success ? 0 : -1;
}

/*
 * alert_should_alert - Check if alert should be sent
 * Returns: 1 if alert should be sent, 0 otherwise
 */
int alert_should_alert(const char *state_file, const char *check_name, 
                       int threshold_hours) {
    char path[512];
    char cmd[1024];
    FILE *fp;
    time_t last_alert = 0;
    time_t now = time(NULL);
    
    if (!state_file || !check_name) {
        return 1;
    }
    
    snprintf(path, sizeof(path), "/var/run/syssec/%s_%s", state_file, check_name);
    
    /* Create directory */
    snprintf(cmd, sizeof(cmd), "mkdir -p /var/run/syssec 2>/dev/null");
    system(cmd);
    
    /* Check if alert was sent recently */
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%ld", &last_alert);
        fclose(fp);
    }
    
    if (last_alert > 0 && (now - last_alert) < (threshold_hours * 3600)) {
        return 0; /* Alert was sent recently */
    }
    
    /* Update timestamp */
    fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%ld", now);
        fclose(fp);
    }
    
    return 1;
}
