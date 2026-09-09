/*
 * report.c - Report generation for SYSSEC tools
 * 
 * Supports JSON, HTML, and plain text output formats.
 * 
 * Compile: cc -Wall -Wextra -O2 -c report.c -o report.o
 */

#define __BSD_VISIBLE 1

#include "report.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ============================================================
 * REPORT INITIALIZATION
 * ============================================================ */

void report_init(syssec_report_t *report) {
    if (!report) return;
    
    memset(report, 0, sizeof(syssec_report_t));
    
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(report->timestamp, sizeof(report->timestamp), 
             "%Y-%m-%d %H:%M:%S", tm);
    
    util_get_hostname(report->hostname, sizeof(report->hostname));
    strncpy(report->syssec_version, SYSSEC_VERSION, sizeof(report->syssec_version) - 1);
    report->passed = 0;
    report->warnings = 0;
    report->failed = 0;
    report->total = 0;
    report->data = NULL;
    report->data_size = 0;
}

void report_add_entry(syssec_report_t *report, syssec_report_entry_t *entry) {
    if (!report || !entry) return;
    
    /* Update counts */
    switch (entry->status) {
        case STATUS_PASS: report->passed++; break;
        case STATUS_WARN: report->warnings++; break;
        case STATUS_FAIL: report->failed++; break;
        default: break;
    }
    report->total++;
    
    /* Data is stored separately - this is just for counting */
}

/* ============================================================
 * REPORT GENERATION: TEXT
 * ============================================================ */

char* report_generate_text(syssec_report_t *report) {
    char *buffer;
    size_t size = 8192;
    size_t offset = 0;
    
    if (!report) {
        return NULL;
    }
    
    buffer = malloc(size);
    if (!buffer) {
        return NULL;
    }
    
    offset += snprintf(buffer + offset, size - offset,
                       "╔═══════════════════════════════════════════════════════════════╗\n");
    offset += snprintf(buffer + offset, size - offset,
                       "║                    SYSSEC REPORT                           ║\n");
    offset += snprintf(buffer + offset, size - offset,
                       "╚═══════════════════════════════════════════════════════════════╝\n");
    offset += snprintf(buffer + offset, size - offset,
                       "\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  Hostname:   %s\n", report->hostname);
    offset += snprintf(buffer + offset, size - offset,
                       "  Timestamp:  %s\n", report->timestamp);
    offset += snprintf(buffer + offset, size - offset,
                       "  Version:    %s\n", report->syssec_version);
    offset += snprintf(buffer + offset, size - offset,
                       "\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  ──────────────────────────────────────────────────────────\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  SUMMARY:\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    Passed:   %d\n", report->passed);
    offset += snprintf(buffer + offset, size - offset,
                       "    Warnings: %d\n", report->warnings);
    offset += snprintf(buffer + offset, size - offset,
                       "    Failed:   %d\n", report->failed);
    offset += snprintf(buffer + offset, size - offset,
                       "    Total:    %d\n", report->total);
    offset += snprintf(buffer + offset, size - offset,
                       "  ──────────────────────────────────────────────────────────\n");
    
    /* Note: Individual entries are stored elsewhere, but we include summary */
    
    return buffer;
}

/* ============================================================
 * REPORT GENERATION: HTML
 * ============================================================ */

char* report_generate_html(syssec_report_t *report) {
    char *buffer;
    size_t size = 16384;
    size_t offset = 0;
    
    if (!report) {
        return NULL;
    }
    
    buffer = malloc(size);
    if (!buffer) {
        return NULL;
    }
    
    offset += snprintf(buffer + offset, size - offset,
                       "<!DOCTYPE html>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "<html>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "<head>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  <meta charset=\"UTF-8\">\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  <title>SYSSEC Report</title>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  <style>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    body { font-family: monospace; margin: 40px; background: #f5f5f5; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .pass { color: #4CAF50; font-weight: bold; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .warn { color: #FF9800; font-weight: bold; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .fail { color: #f44336; font-weight: bold; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .summary { display: flex; gap: 20px; margin: 20px 0; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .summary-item { padding: 10px 20px; border-radius: 4px; background: #f0f0f0; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .check { margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .check .status { font-weight: bold; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .check .message { margin: 5px 0; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    .check .recommendation { background: #fff3cd; padding: 8px; border-radius: 4px; margin-top: 5px; }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  </style>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "</head>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "<body>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  <div class=\"container\">\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    <h1>SYSSEC Security Report</h1>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    <p><strong>Hostname:</strong> %s</p>\n", report->hostname);
    offset += snprintf(buffer + offset, size - offset,
                       "    <p><strong>Timestamp:</strong> %s</p>\n", report->timestamp);
    offset += snprintf(buffer + offset, size - offset,
                       "    <p><strong>Version:</strong> %s</p>\n", report->syssec_version);
    offset += snprintf(buffer + offset, size - offset,
                       "\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    <div class=\"summary\">\n");
    offset += snprintf(buffer + offset, size - offset,
                       "      <div class=\"summary-item\"><span class=\"pass\">✓ Passed:</span> %d</div>\n", report->passed);
    offset += snprintf(buffer + offset, size - offset,
                       "      <div class=\"summary-item\"><span class=\"warn\">⚠ Warnings:</span> %d</div>\n", report->warnings);
    offset += snprintf(buffer + offset, size - offset,
                       "      <div class=\"summary-item\"><span class=\"fail\">✗ Failed:</span> %d</div>\n", report->failed);
    offset += snprintf(buffer + offset, size - offset,
                       "      <div class=\"summary-item\"><strong>Total:</strong> %d</div>\n", report->total);
    offset += snprintf(buffer + offset, size - offset,
                       "    </div>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    <p><em>No detailed entries available in this report.</em></p>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  </div>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "</body>\n");
    offset += snprintf(buffer + offset, size - offset,
                       "</html>\n");
    
    return buffer;
}

/* ============================================================
 * REPORT GENERATION: JSON
 * ============================================================ */

char* report_generate_json(syssec_report_t *report) {
    char *buffer;
    size_t size = 4096;
    size_t offset = 0;
    
    if (!report) {
        return NULL;
    }
    
    buffer = malloc(size);
    if (!buffer) {
        return NULL;
    }
    
    offset += snprintf(buffer + offset, size - offset,
                       "{\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  \"report\": {\n");
    offset += snprintf(buffer + offset, size - offset,
                       "    \"hostname\": \"%s\",\n", report->hostname);
    offset += snprintf(buffer + offset, size - offset,
                       "    \"timestamp\": \"%s\",\n", report->timestamp);
    offset += snprintf(buffer + offset, size - offset,
                       "    \"version\": \"%s\",\n", report->syssec_version);
    offset += snprintf(buffer + offset, size - offset,
                       "    \"summary\": {\n");
    offset += snprintf(buffer + offset, size - offset,
                       "      \"passed\": %d,\n", report->passed);
    offset += snprintf(buffer + offset, size - offset,
                       "      \"warnings\": %d,\n", report->warnings);
    offset += snprintf(buffer + offset, size - offset,
                       "      \"failed\": %d,\n", report->failed);
    offset += snprintf(buffer + offset, size - offset,
                       "      \"total\": %d\n", report->total);
    offset += snprintf(buffer + offset, size - offset,
                       "    }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "  }\n");
    offset += snprintf(buffer + offset, size - offset,
                       "}\n");
    
    return buffer;
}

/* ============================================================
 * REPORT SAVE
 * ============================================================ */

syssec_error_t report_save(syssec_report_t *report, const char *dir, 
                           const char *name, const char *format) {
    char path[512];
    char *data = NULL;
    syssec_error_t result = SYSSEC_OK;
    
    if (!report || !dir || !name || !format) {
        return SYSSEC_ERR_INVALID;
    }
    
    /* Generate the report data */
    if (strcmp(format, "json") == 0) {
        data = report_generate_json(report);
    } else if (strcmp(format, "html") == 0) {
        data = report_generate_html(report);
    } else {
        data = report_generate_text(report);
    }
    
    if (!data) {
        return SYSSEC_ERR_NO_MEMORY;
    }
    
    /* Create directory if it doesn't exist */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s 2>/dev/null", dir);
    system(cmd);
    
    /* Write file */
    snprintf(path, sizeof(path), "%s/%s.%s", dir, name, format);
    if (util_write_file(path, data, 0) != SYSSEC_OK) {
        result = SYSSEC_ERR_IO;
    }
    
    free(data);
    return result;
}

/* ============================================================
 * REPORT CLEANUP
 * ============================================================ */

void report_cleanup_old(const char *dir, int retention_days) {
    char cmd[512];
    if (!dir || retention_days <= 0) {
        return;
    }
    
    snprintf(cmd, sizeof(cmd), 
             "find %s -type f -mtime +%d -delete 2>/dev/null", 
             dir, retention_days);
    system(cmd);
}

/* ============================================================
 * REPORT FREE
 * ============================================================ */

void report_free(syssec_report_t *report) {
    if (!report) {
        return;
    }
    
    if (report->data) {
        free(report->data);
        report->data = NULL;
    }
    report->data_size = 0;
}
