/*
 * report.c - Report generation for SYSSEC tools
 * 
 * Supports JSON and HTML output formats.
 * 
 * Compile: cc -Wall -Wextra -O2 -c report.c -o report.o
 */

#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ============================================================
 * REPORT STRUCTURES
 * ============================================================ */

typedef struct {
    char timestamp[64];
    char hostname[256];
    char kernel[256];
    int passed;
    int warnings;
    int failed;
    int total;
    char *data;  /* JSON or HTML content */
} syssec_report_t;

/* ============================================================
 * JSON OUTPUT
 * ============================================================ */

void report_json_start(FILE *fp) {
    fprintf(fp, "{\n");
    fprintf(fp, "  \"timestamp\": \"%s\",\n", ctime(&(time_t){time(NULL)}));
    fprintf(fp, "  \"hostname\": \"%s\",\n", "unknown");
    fprintf(fp, "  \"results\": [\n");
}

void report_json_check(FILE *fp, const char *name, const char *status, 
                       const char *message, const char *recommendation) {
    fprintf(fp, "    {\n");
    fprintf(fp, "      \"name\": \"%s\",\n", name);
    fprintf(fp, "      \"status\": \"%s\",\n", status);
    fprintf(fp, "      \"message\": \"%s\",\n", message);
    fprintf(fp, "      \"recommendation\": \"%s\"\n", recommendation);
    fprintf(fp, "    },\n");
}

void report_json_end(FILE *fp) {
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
}

/* ============================================================
 * HTML OUTPUT
 * ============================================================ */

void report_html_start(FILE *fp, const char *title) {
    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html>\n");
    fprintf(fp, "<head>\n");
    fprintf(fp, "  <title>%s</title>\n", title);
    fprintf(fp, "  <style>\n");
    fprintf(fp, "    body { font-family: monospace; margin: 40px; }\n");
    fprintf(fp, "    h1 { color: #333; }\n");
    fprintf(fp, "    .pass { color: green; }\n");
    fprintf(fp, "    .warn { color: orange; }\n");
    fprintf(fp, "    .fail { color: red; }\n");
    fprintf(fp, "    .check { margin: 10px 0; padding: 10px; border: 1px solid #ddd; }\n");
    fprintf(fp, "    .recommendation { background: #f0f0f0; padding: 5px; }\n");
    fprintf(fp, "  </style>\n");
    fprintf(fp, "</head>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "  <h1>%s</h1>\n", title);
    fprintf(fp, "  <p>Generated: %s</p>\n", ctime(&(time_t){time(NULL)}));
    fprintf(fp, "  <hr>\n");
}

void report_html_check(FILE *fp, const char *name, const char *status,
                       const char *message, const char *recommendation) {
    const char *css_class = "pass";
    if (strcmp(status, "WARN") == 0) css_class = "warn";
    if (strcmp(status, "FAIL") == 0) css_class = "fail";
    
    fprintf(fp, "  <div class=\"check\">\n");
    fprintf(fp, "    <h3 class=\"%s\">%s: %s</h3>\n", css_class, status, name);
    fprintf(fp, "    <p>%s</p>\n", message);
    if (recommendation && recommendation[0] != '\0') {
        fprintf(fp, "    <div class=\"recommendation\">\n");
        fprintf(fp, "      <strong>Recommendation:</strong> %s\n", recommendation);
        fprintf(fp, "    </div>\n");
    }
    fprintf(fp, "  </div>\n");
}

void report_html_end(FILE *fp) {
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");
}

/* ============================================================
 * REPORT MANAGEMENT
 * ============================================================ */

int report_save(const char *dir, const char *name, const char *data) {
    char path[512];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[64];
    
    if (!dir || !name || !data) {
        return -1;
    }
    
    /* Create directory */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s 2>/dev/null", dir);
    system(cmd);
    
    /* Create filename with timestamp */
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm);
    snprintf(path, sizeof(path), "%s/%s_%s.html", dir, name, timestamp);
    
    FILE *fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }
    
    fprintf(fp, "%s", data);
    fclose(fp);
    
    return 0;
}

void report_cleanup_old(const char *dir, int retention_days) {
    char cmd[512];
    if (!dir || retention_days <= 0) return;
    
    snprintf(cmd, sizeof(cmd), "find %s -type f -mtime +%d -delete 2>/dev/null", 
             dir, retention_days);
    system(cmd);
}
