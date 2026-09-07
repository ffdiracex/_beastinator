/*
 * scanner.h - Core System Scanner for SYSSEC
 * 
 * Provides system scanning functionality including:
 * - System information collection
 * - Process analysis
 * - User account auditing
 * - Filesystem security checks
 * - Network security scanning
 * - Service status checking
 * - Security configuration verification
 * - Log analysis
 * - Update status checking
 * - TTY security scanning
 *
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_SCANNER_H
#define SYSSEC_SCANNER_H

#include "syssec.h"
#include "config.h"
#include "report.h"

/* ============================================================
 * SCANNER STATE
 * ============================================================ */
/* ============================================================
 * BANNER FUNCTION
 * ============================================================ */

static inline void syssec_banner(void) {
    printf(COLOR_CYAN "╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    SYSSEC - System Security Tools                  ║\n");
    printf("║                    FreeBSD Security Toolkit                        ║\n");
    printf("║                    Version %s                                      ║\n", SYSSEC_VERSION);
    printf("╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
}



/*
 * Opaque scanner state structure
 * The actual implementation is in scanner.c
 */
typedef struct scanner_state scanner_state_t;

/* ============================================================
 * SCAN RESULT ENTRY
 * ============================================================ */

typedef struct {
    char name[128];                 /* Check name */
    char description[512];          /* Description of the check */
    char recommendation[512];       /* Recommendation if failed */
    syssec_severity_t severity;     /* Critical, Warning, Info */
    syssec_status_t status;         /* Pass, Warn, Fail */
    char category[64];              /* Category: System, Security, etc. */
} scanner_result_t;

/* ============================================================
 * SCANNER FUNCTIONS
 * ============================================================ */

/*
 * scanner_init - Initialize the scanner
 * 
 * @param config: Pointer to configuration structure
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scanner_init(syssec_config_t *config);

/*
 * scanner_run - Run the system scan
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scanner_run(void);

/*
 * scanner_get_results - Get number of scan results
 * 
 * Returns: Number of results
 */
int scanner_get_results(void);

/*
 * scanner_get_result - Get a specific result
 * 
 * @param index: Index of the result
 * @param result: Output pointer for result
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scanner_get_result(int index, scanner_result_t *result);

/*
 * scanner_get_results_by_category - Get results filtered by category
 * 
 * @param category: Category to filter by
 * @param results: Output array of results (will be allocated)
 * @param count: Output count
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scanner_get_results_by_category(const char *category, 
                                               scanner_result_t **results, 
                                               int *count);

/*
 * scanner_get_results_by_status - Get results filtered by status
 * 
 * @param status: Status to filter by
 * @param results: Output array of results (will be allocated)
 * @param count: Output count
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scanner_get_results_by_status(syssec_status_t status,
                                             scanner_result_t **results,
                                             int *count);

/*
 * scanner_get_critical_count - Get number of critical failures
 * 
 * Returns: Number of critical issues
 */
int scanner_get_critical_count(void);

/*
 * scanner_get_warning_count - Get number of warnings
 * 
 * Returns: Number of warnings
 */
int scanner_get_warning_count(void);

/*
 * scanner_get_pass_count - Get number of passed checks
 * 
 * Returns: Number of passed checks
 */
int scanner_get_pass_count(void);

/*
 * scanner_export_to_report - Export scan results to a report
 * 
 * @param report: Pointer to report structure
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t scanner_export_to_report(syssec_report_t *report);

/*
 * scanner_print_summary - Print scan summary to stdout
 */
void scanner_print_summary(void);

/*
 * scanner_print_results - Print all scan results to stdout
 */
void scanner_print_results(void);

/*
 * scanner_print_results_by_category - Print results filtered by category
 * 
 * @param category: Category to filter by
 */
void scanner_print_results_by_category(const char *category);

/*
 * scanner_print_critical - Print only critical results
 */
void scanner_print_critical(void);

/*
 * scanner_has_critical - Check if any critical issues were found
 * 
 * Returns: 1 if critical issues found, 0 otherwise
 */
int scanner_has_critical(void);

/*
 * scanner_has_warnings - Check if any warnings were found
 * 
 * Returns: 1 if warnings found, 0 otherwise
 */
int scanner_has_warnings(void);

/*
 * scanner_get_hostname - Get scanned hostname
 * 
 * Returns: Pointer to hostname string
 */
const char* scanner_get_hostname(void);

/*
 * scanner_get_kernel - Get kernel version
 * 
 * Returns: Pointer to kernel version string
 */
const char* scanner_get_kernel(void);

/*
 * scanner_get_timestamp - Get scan timestamp
 * 
 * Returns: Scan timestamp
 */
time_t scanner_get_timestamp(void);

/*
 * scanner_is_initialized - Check if scanner is initialized
 * 
 * Returns: 1 if initialized, 0 otherwise
 */
int scanner_is_initialized(void);

/*
 * scanner_cleanup - Clean up scanner resources
 */
void scanner_cleanup(void);

/*
 * scanner_get_results_json - Get results as JSON string
 * 
 * Returns: JSON string (must be freed by caller), NULL on error
 */
char* scanner_get_results_json(void);

/*
 * scanner_get_summary_json - Get summary as JSON string
 * 
 * Returns: JSON string (must be freed by caller), NULL on error
 */
char* scanner_get_summary_json(void);

/*
 * scanner_check_system - Run system information checks
 */
void scanner_check_system(void);

/*
 * scanner_check_processes - Run process checks
 */
void scanner_check_processes(void);

/*
 * scanner_check_users - Run user account checks
 */
void scanner_check_users(void);

/*
 * scanner_check_filesystem - Run filesystem checks
 */
void scanner_check_filesystem(void);

/*
 * scanner_check_network - Run network checks
 */
void scanner_check_network(void);

/*
 * scanner_check_services - Run service checks
 */
void scanner_check_services(void);

/*
 * scanner_check_security - Run security configuration checks
 */
void scanner_check_security(void);

/*
 * scanner_check_logs - Run log checks
 */
void scanner_check_logs(void);

/*
 * scanner_check_updates - Run update checks
 */
void scanner_check_updates(void);

/*
 * scanner_check_ttys - Run TTY security checks
 */
void scanner_check_ttys(void);

/*
 * scanner_check_firewall - Run firewall checks
 */
void scanner_check_firewall(void);

/*
 * scanner_check_ssh - Run SSH configuration checks
 */
void scanner_check_ssh(void);

/*
 * scanner_check_permissions - Run file permission checks
 */
void scanner_check_permissions(void);

#endif /* SYSSEC_SCANNER_H */
