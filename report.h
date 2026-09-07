/*
 * report.h - Report generation for SYSSEC tools
 * 
 * Supports JSON, HTML, and plain text output formats.
 * 
 * Copyright (c) 2024 SYSSEC Project
 */

#ifndef SYSSEC_REPORT_H
#define SYSSEC_REPORT_H

#include "syssec.h"

/* ============================================================
 * REPORT STRUCTURES
 * ============================================================ */

typedef struct {
    char timestamp[64];
    char hostname[MAX_NAME];
    char kernel_version[MAX_STRING];
    char syssec_version[32];
    int passed;
    int warnings;
    int failed;
    int total;
    char *data;
    size_t data_size;
} syssec_report_t;

typedef struct {
    char name[MAX_NAME];
    syssec_status_t status;
    syssec_severity_t severity;
    char message[MAX_STRING];
    char recommendation[MAX_STRING];
    char category[MAX_NAME];
} syssec_report_entry_t;

/* ============================================================
 * FUNCTION PROTOTYPES
 * ============================================================ */

/*
 * report_init - Initialize report
 * 
 * @param report: Pointer to report structure
 */
void report_init(syssec_report_t *report);

/*
 * report_add_entry - Add entry to report
 * 
 * @param report: Pointer to report structure
 * @param entry: Pointer to entry structure
 */
void report_add_entry(syssec_report_t *report, syssec_report_entry_t *entry);

/*
 * report_generate_json - Generate JSON report
 * 
 * @param report: Pointer to report structure
 * @param output: Output buffer (can be NULL to use internal)
 * 
 * Returns: Pointer to JSON string
 */
char* report_generate_json(syssec_report_t *report);

/*
 * report_generate_html - Generate HTML report
 * 
 * @param report: Pointer to report structure
 * @param output: Output buffer (can be NULL to use internal)
 * 
 * Returns: Pointer to HTML string
 */
char* report_generate_html(syssec_report_t *report);

/*
 * report_generate_text - Generate plain text report
 * 
 * @param report: Pointer to report structure
 * @param output: Output buffer (can be NULL to use internal)
 * 
 * Returns: Pointer to text string
 */
char* report_generate_text(syssec_report_t *report);

/*
 * report_save - Save report to file
 * 
 * @param report: Pointer to report structure
 * @param dir: Directory to save in
 * @param name: Report name
 * @param format: "json", "html", or "text"
 * 
 * Returns: SYSSEC_OK on success, error code on failure
 */
syssec_error_t report_save(syssec_report_t *report, const char *dir, 
                           const char *name, const char *format);

/*
 * report_cleanup_old - Remove old reports
 * 
 * @param dir: Directory to clean
 * @param retention_days: Keep reports newer than this
 */
void report_cleanup_old(const char *dir, int retention_days);

/*
 * report_free - Free report data
 * 
 * @param report: Pointer to report structure
 */
void report_free(syssec_report_t *report);

#endif /* SYSSEC_REPORT_H */
