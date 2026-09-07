/*
 * scheduler.c - Cron scheduler for SYSSEC tools
 * 
 * Installs and manages cron jobs for automated scanning.
 * 
 * Compile: cc -Wall -Wextra -O2 -c scheduler.c -o scheduler.o
 */

#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

/* ============================================================
 * SCHEDULER FUNCTIONS
 * ============================================================ */

/*
 * scheduler_install - Install cron job
 * Returns: 0 on success, -1 on error
 */
int scheduler_install(const char *schedule, const char *command) {
    char tmp_path[256];
    char cmd[1024];
    FILE *fp;
    int found = 0;
    
    if (!schedule || !command) {
        return -1;
    }
    
    /* Check if already installed */
    snprintf(cmd, sizeof(cmd), "crontab -l 2>/dev/null | grep -q '%s'", command);
    if (system(cmd) == 0) {
        return 0; /* Already installed */
    }
    
    /* Create temporary file */
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/crontab_%d", getpid());
    
    /* Get current crontab */
    snprintf(cmd, sizeof(cmd), "crontab -l 2>/dev/null > %s", tmp_path);
    system(cmd);
    
    /* Append new job */
    fp = fopen(tmp_path, "a");
    if (!fp) {
        return -1;
    }
    
    fprintf(fp, "# SYSSEC scheduled scan - %s\n", ctime(&(time_t){time(NULL)}));
    fprintf(fp, "%s %s\n", schedule, command);
    fclose(fp);
    
    /* Install new crontab */
    snprintf(cmd, sizeof(cmd), "crontab %s", tmp_path);
    int result = system(cmd);
    
    /* Clean up */
    unlink(tmp_path);
    
    return result;
}

/*
 * scheduler_remove - Remove cron job
 * Returns: 0 on success, -1 on error
 */
int scheduler_remove(const char *command) {
    char tmp_path[256];
    char cmd[1024];
    FILE *fp_in, *fp_out;
    char line[1024];
    int found = 0;
    
    if (!command) {
        return -1;
    }
    
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/crontab_%d", getpid());
    
    /* Get current crontab */
    snprintf(cmd, sizeof(cmd), "crontab -l 2>/dev/null > %s", tmp_path);
    system(cmd);
    
    fp_in = fopen(tmp_path, "r");
    if (!fp_in) {
        return -1;
    }
    
    fp_out = fopen("/tmp/crontab_new", "w");
    if (!fp_out) {
        fclose(fp_in);
        return -1;
    }
    
    /* Filter out the job */
    while (fgets(line, sizeof(line), fp_in)) {
        if (strstr(line, command) == NULL && strstr(line, "SYSSEC") == NULL) {
            fprintf(fp_out, "%s", line);
        } else {
            found = 1;
        }
    }
    
    fclose(fp_in);
    fclose(fp_out);
    
    if (found) {
        snprintf(cmd, sizeof(cmd), "crontab /tmp/crontab_new");
        system(cmd);
    }
    
    unlink(tmp_path);
    unlink("/tmp/crontab_new");
    
    return 0;
}

/*
 * scheduler_status - Check if cron job is installed
 * Returns: 1 if installed, 0 if not
 */
int scheduler_status(const char *command) {
    char cmd[1024];
    
    if (!command) {
        return 0;
    }
    
    snprintf(cmd, sizeof(cmd), "crontab -l 2>/dev/null | grep -q '%s'", command);
    return (system(cmd) == 0);
}

/*
 * scheduler_list - List all SYSSEC cron jobs
 */
void scheduler_list(void) {
    printf("\n" COLOR_BOLD "=== SYSSEC CRON JOBS ===\n" COLOR_RESET);
    printf("────────────────────────────────────────────\n");
    
    system("crontab -l 2>/dev/null | grep -E 'SYSSEC|syssec' || echo '  No SYSSEC cron jobs installed'");
}
