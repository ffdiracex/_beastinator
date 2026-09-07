/*
 * security_audit.c - System Security Auditor for FreeBSD
 * 
 * This program checks the system's security posture and provides
 * specific recommendations for hardening.
 * 
 * Compile: cc -Wall -Wextra -O2 security_audit.c -o security_audit
 * Run: sudo ./security_audit
 */

#define __BSD_VISIBLE 1

#include "syssec.h"
#include "config.h"
#include "logging.h"
#include "report.h"
#include "alert.h"
#include "utils.h"

/* ============================================================
 * DATA STRUCTURES
 * ============================================================ */

typedef struct {
    char name[128];
    char description[512];
    char recommendation[512];
    syssec_severity_t severity;
    syssec_status_t status;
} audit_check_t;

#define MAX_CHECKS 256
static audit_check_t checks[MAX_CHECKS];
static int num_checks = 0;
static syssec_config_t config;
static syssec_report_t report;

/* ============================================================
 * CHECK FUNCTIONS
 * ============================================================ */

void add_check(const char *name, const char *desc, 
               const char *rec, syssec_severity_t severity, 
               syssec_status_t status) {
    if (num_checks >= MAX_CHECKS) return;
    
    strncpy(checks[num_checks].name, name, sizeof(checks[num_checks].name) - 1);
    strncpy(checks[num_checks].description, desc, sizeof(checks[num_checks].description) - 1);
    strncpy(checks[num_checks].recommendation, rec, sizeof(checks[num_checks].recommendation) - 1);
    checks[num_checks].severity = severity;
    checks[num_checks].status = status;
    num_checks++;
}

void check_services(void) {
    const struct {
        const char *service;
        const char *name;
        int critical;
    } services[] = {
        {"sshd", "SSH Server", 1},
        {"telnetd", "Telnet Server", 2},
        {"ftpd", "FTP Server", 1},
        {"sendmail", "Sendmail", 1},
        {"inetd", "inetd", 2},
        {"cron", "Cron", 0},
        {"syslogd", "Syslog", 0},
        {"ntpd", "NTP Daemon", 0},
        {NULL, NULL, 0}
    };
    
    for (int i = 0; services[i].service != NULL; i++) {
        int running = util_process_running(services[i].service);
        char desc[512];
        char rec[512];
        
        snprintf(desc, sizeof(desc), "Service '%s' is %s", 
                 services[i].name, running ? "running" : "stopped");
        
        snprintf(rec, sizeof(rec), "Service '%s' should be %s unless explicitly needed",
                 services[i].name, running ? "disabled if not needed" : "enabled if required");
        
        syssec_status_t status = STATUS_PASS;
        if (running && services[i].critical == 2) {
            status = STATUS_FAIL;
        } else if (!running && services[i].critical == 2) {
            status = STATUS_WARN;
        }
        
        add_check(services[i].name, desc, rec, 
                 services[i].critical == 2 ? SEVERITY_CRITICAL : SEVERITY_WARNING,
                 status);
    }
}

void check_firewall(void) {
    int pf_enabled = util_process_running("pfctl");
    int ipfw_enabled = util_process_running("ipfw");
    
    if (pf_enabled || ipfw_enabled) {
        add_check("Firewall", "A firewall is running", 
                 "Keep firewall enabled", SEVERITY_INFO, STATUS_PASS);
    } else {
        add_check("Firewall", "No firewall appears to be running",
                 "Enable PF: add 'pf_enable=\"YES\"' to /etc/rc.conf", 
                 SEVERITY_CRITICAL, STATUS_FAIL);
    }
}

void check_ssh_config(void) {
    FILE *fp = fopen("/etc/ssh/sshd_config", "r");
    if (!fp) {
        add_check("SSH Config", "Cannot read /etc/ssh/sshd_config",
                 "Ensure SSH is installed and configured", 
                 SEVERITY_WARNING, STATUS_FAIL);
        return;
    }
    
    char line[1024];
    int permit_root = 0;
    int password_auth = 0;
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;
        
        if (strstr(line, "PermitRootLogin")) {
            found++;
            if (strstr(line, "yes") && !strstr(line, "without-password")) {
                permit_root = 1;
            }
        }
        if (strstr(line, "PasswordAuthentication")) {
            found++;
            if (strstr(line, "yes")) {
                password_auth = 1;
            }
        }
    }
    fclose(fp);
    
    if (permit_root) {
        add_check("SSH Root Login", "PermitRootLogin is enabled",
                 "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password'",
                 SEVERITY_CRITICAL, STATUS_FAIL);
    } else {
        add_check("SSH Root Login", "PermitRootLogin is properly restricted",
                 "Keep root login disabled", SEVERITY_INFO, STATUS_PASS);
    }
    
    if (password_auth) {
        add_check("SSH Password Auth", "PasswordAuthentication is enabled",
                 "Use key-based authentication and disable passwords",
                 SEVERITY_WARNING, STATUS_WARN);
    } else {
        add_check("SSH Password Auth", "PasswordAuthentication is disabled",
                 "Keep password authentication disabled", SEVERITY_INFO, STATUS_PASS);
    }
}

void check_sysctl_security(void) {
    const struct {
        const char *name;
        const char *expected;
        const char *desc;
        int severity;
    } settings[] = {
        {"net.inet.tcp.syncookies", "1", "TCP SYN cookies", 0},
        {"net.inet.ip.forwarding", "0", "IP forwarding", 1},
        {"security.bsd.see_other_uids", "0", "See other UIDs", 1},
        {"kern.securelevel", "0", "Securelevel", 1},
        {NULL, NULL, NULL, 0}
    };
    
    for (int i = 0; settings[i].name != NULL; i++) {
        char value[256];
        size_t len = sizeof(value);
        
        if (sysctlbyname(settings[i].name, value, &len, NULL, 0) == 0) {
            char *nl = strchr(value, '\n');
            if (nl) *nl = '\0';
            
            char desc[512];
            snprintf(desc, sizeof(desc), "%s = %s (expected %s)", 
                     settings[i].name, value, settings[i].expected);
            
            char rec[512];
            snprintf(rec, sizeof(rec), "Set '%s=%s' in /etc/sysctl.conf", 
                     settings[i].name, settings[i].expected);
            
            syssec_status_t status = STATUS_PASS;
            if (strcmp(value, settings[i].expected) != 0) {
                status = STATUS_WARN;
            }
            
            add_check(settings[i].name, desc, rec, 
                     settings[i].severity ? SEVERITY_WARNING : SEVERITY_INFO, status);
        }
    }
}

void check_filesystem_permissions(void) {
    const struct {
        const char *path;
        mode_t expected;
        const char *desc;
        int severity;
    } files[] = {
        {"/etc/passwd", 0644, "Passwd file", 1},
        {"/etc/master.passwd", 0600, "Master passwd", 2},
        {"/etc/group", 0644, "Group file", 1},
        {"/etc/sudoers", 0440, "Sudoers", 2},
        {"/etc/ssh/sshd_config", 0644, "SSH config", 1},
        {NULL, 0, NULL, 0}
    };
    
    for (int i = 0; files[i].path != NULL; i++) {
        struct stat st;
        if (stat(files[i].path, &st) < 0) {
            char desc[512];
            snprintf(desc, sizeof(desc), "%s does not exist", files[i].path);
            add_check(files[i].path, desc, "File should exist with proper permissions",
                     files[i].severity == 2 ? SEVERITY_CRITICAL : SEVERITY_WARNING,
                     STATUS_FAIL);
            continue;
        }
        
        mode_t mode = st.st_mode & 0777;
        char desc[512];
        snprintf(desc, sizeof(desc), "%s permissions: %03o", files[i].path, mode);
        
        char rec[512];
        snprintf(rec, sizeof(rec), "Set permissions to %03o", files[i].expected);
        
        syssec_status_t status = STATUS_PASS;
        if (mode != files[i].expected) {
            status = (st.st_mode & S_IWOTH) ? STATUS_FAIL : STATUS_WARN;
        }
        
        add_check(files[i].path, desc, rec, 
                 files[i].severity == 2 ? SEVERITY_CRITICAL : SEVERITY_WARNING, status);
    }
}

void check_user_security(void) {
    struct passwd *pw;
    int root_users = 0;
    uid_t uids[1024];
    int uid_count = 0;
    int duplicate_uids = 0;
    
    setpwent();
    while ((pw = getpwent()) != NULL) {
        if (pw->pw_uid == 0 && strcmp(pw->pw_name, "root") != 0) {
            root_users++;
        }
        
        for (int i = 0; i < uid_count; i++) {
            if (uids[i] == pw->pw_uid && pw->pw_uid != 0) {
                duplicate_uids++;
                break;
            }
        }
        uids[uid_count++] = pw->pw_uid;
    }
    endpwent();
    
    if (root_users > 0) {
        char desc[512];
        snprintf(desc, sizeof(desc), "Found %d additional UID 0 users", root_users);
        add_check("Root accounts", desc, "Remove additional UID 0 users",
                 SEVERITY_CRITICAL, STATUS_FAIL);
    } else {
        add_check("Root accounts", "Only root has UID 0",
                 "Keep UID 0 restricted to root", SEVERITY_INFO, STATUS_PASS);
    }
    
    if (duplicate_uids > 0) {
        add_check("Duplicate UIDs", "Duplicate UIDs found",
                 "Ensure each user has unique UID", SEVERITY_WARNING, STATUS_WARN);
    }
}

void check_logging(void) {
    const char *log_files[] = {
        "/var/log/messages",
        "/var/log/auth.log",
        "/var/log/secure",
        NULL
    };
    
    int found = 0;
    for (int i = 0; log_files[i] != NULL; i++) {
        if (util_file_exists(log_files[i])) {
            found++;
        }
    }
    
    if (found < 2) {
        add_check("Logging", "Some system log files are missing",
                 "Configure syslogd to properly log to /var/log/",
                 SEVERITY_WARNING, STATUS_WARN);
    } else {
        add_check("Logging", "System logs appear to be present",
                 "Check syslog.conf for proper configuration",
                 SEVERITY_INFO, STATUS_PASS);
    }
}

void check_updates(void) {
    if (util_file_exists("/usr/sbin/freebsd-update")) {
        add_check("FreeBSD Updates", "freebsd-update is available",
                 "Run 'freebsd-update fetch install' regularly",
                 SEVERITY_INFO, STATUS_PASS);
    } else {
        add_check("FreeBSD Updates", "freebsd-update is not available",
                 "Install freebsd-update or use alternative update method",
                 SEVERITY_WARNING, STATUS_WARN);
    }
}

/* ============================================================
 * PRINT FUNCTIONS
 * ============================================================ */

void print_summary(void) {
    int critical_fail = 0, warning_fail = 0, info_fail = 0;
    
    for (int i = 0; i < num_checks; i++) {
        if (checks[i].status != STATUS_PASS) {
            switch (checks[i].severity) {
                case SEVERITY_CRITICAL: critical_fail++; break;
                case SEVERITY_WARNING: warning_fail++; break;
                default: info_fail++; break;
            }
        }
    }
    
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    AUDIT SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    printf("  Total checks: %d\n", num_checks);
    printf("  %sCritical:%s %d\n", COLOR_RED, COLOR_RESET, critical_fail);
    printf("  %sWarnings:%s %d\n", COLOR_YELLOW, COLOR_RESET, warning_fail);
    printf("  %sInfo:%s %d\n", COLOR_BLUE, COLOR_RESET, info_fail);
    printf("  %sPassed:%s %d\n", COLOR_GREEN, COLOR_RESET, 
           num_checks - (critical_fail + warning_fail + info_fail));
    
    if (critical_fail > 0) {
        printf("\n" COLOR_RED "  ⚠ CRITICAL: Address critical issues immediately!\n" COLOR_RESET);
    }
    if (warning_fail > 0) {
        printf(COLOR_YELLOW "  ⚠ WARNING: Address warnings soon\n" COLOR_RESET);
    }
}

void print_recommendations(void) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    RECOMMENDATIONS\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    printf("  %-12s %-20s %s\n", "SEVERITY", "CHECK", "RECOMMENDATION");
    printf("  %-12s %-20s %s\n", "--------", "-----", "-------------");
    
    for (int i = 0; i < num_checks; i++) {
        if (checks[i].status != STATUS_PASS) {
            const char *color = syssec_severity_color(checks[i].severity);
            printf("  %s%-12s%s %-20s %s\n",
                   color, syssec_severity_str(checks[i].severity),
                   COLOR_RESET,
                   checks[i].name,
                   checks[i].recommendation);
        }
    }
    
    printf("\n" COLOR_BOLD "General System Hardening Recommendations:\n" COLOR_RESET);
    printf("\n");
    printf("  1. Enable PF firewall: pf_enable=\"YES\" in /etc/rc.conf\n");
    printf("  2. Disable unnecessary services in /etc/rc.conf\n");
    printf("  3. Run freebsd-update regularly for security patches\n");
    printf("  4. Configure system logging with syslog.conf\n");
    printf("  5. Enable kernel security levels in /etc/sysctl.conf\n");
    printf("  6. Disable root SSH login: PermitRootLogin no\n");
    printf("  7. Use key-based authentication only\n");
    printf("  8. Set proper permissions on sensitive files\n");
    printf("  9. Monitor logs with logwatch or similar\n");
    printf("  10. Regularly audit user accounts\n");
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(int argc, char **argv) {
    int verbose = 0;
    int no_report = 0;
    char config_path[MAX_PATH];
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--no-report") == 0) {
            no_report = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) {
                strncpy(config_path, argv[++i], sizeof(config_path) - 1);
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("  -v, --verbose    Show all checks\n");
            printf("  -c, --config     Use config file\n");
            printf("  --no-report      Don't save report\n");
            printf("  -h, --help       Show this help\n");
            return 0;
        }
    }
    
    /* Load configuration */
    if (config_path[0] == '\0') {
        syssec_config_default_path(config_path, sizeof(config_path));
    }
    syssec_config_load(&config, config_path);
    
    /* Initialize logging */
    log_init(config.log_dir, config.log_file, 
             config.log_level > 2 ? LOG_LEVEL_INFO : LOG_LEVEL_DEBUG);
    
    syssec_banner();
    
    if (!syssec_is_root()) {
        printf(COLOR_YELLOW "\n⚠ Warning: Not running as root.\n" COLOR_RESET);
        printf("  Some checks will be limited.\n");
        printf("  Run with sudo for full auditing.\n\n");
    } else {
        printf(COLOR_GREEN "\n✓ Running as root (full auditing available)\n" COLOR_RESET);
    }
    
    /* Run all checks */
    check_services();
    check_firewall();
    check_ssh_config();
    check_sysctl_security();
    check_filesystem_permissions();
    check_user_security();
    check_logging();
    check_updates();
    
    /* Generate report */
    report_init(&report);
    for (int i = 0; i < num_checks; i++) {
        syssec_report_entry_t entry;
        strncpy(entry.name, checks[i].name, sizeof(entry.name) - 1);
        entry.status = checks[i].status;
        entry.severity = checks[i].severity;
        strncpy(entry.message, checks[i].description, sizeof(entry.message) - 1);
        strncpy(entry.recommendation, checks[i].recommendation, 
                sizeof(entry.recommendation) - 1);
        strncpy(entry.category, "Security", sizeof(entry.category) - 1);
        report_add_entry(&report, &entry);
    }
    
    /* Save report */
    if (!no_report && config.save_reports) {
        report_save(&report, config.report_dir, "security_audit", "html");
        report_save(&report, config.report_dir, "security_audit", "json");
        report_cleanup_old(config.report_dir, config.report_retention_days);
    }
    
    /* Print results */
    print_summary();
    
    if (verbose) {
        /* Print detailed checks */
        printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
        printf("                    DETAILED CHECKS\n");
        printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
        printf("\n");
        
        for (int i = 0; i < num_checks; i++) {
            const char *color = syssec_status_color(checks[i].status);
            printf("  %s[%s]%s %s\n",
                   color,
                   syssec_status_str(checks[i].status),
                   COLOR_RESET,
                   checks[i].name);
            printf("    %s\n", checks[i].description);
            if (checks[i].status != STATUS_PASS) {
                printf("    " COLOR_YELLOW "→ %s" COLOR_RESET "\n", checks[i].recommendation);
            }
            printf("\n");
        }
    } else {
        print_recommendations();
    }
    
    /* Send alerts for critical issues */
    if (config.enable_alerts) {
        int critical_found = 0;
        char alert_msg[4096] = {0};
        
        for (int i = 0; i < num_checks; i++) {
            if (checks[i].severity == SEVERITY_CRITICAL && 
                checks[i].status != STATUS_PASS) {
                critical_found++;
                char line[512];
                snprintf(line, sizeof(line), "  - %s: %s\n", 
                        checks[i].name, checks[i].description);
                strncat(alert_msg, line, sizeof(alert_msg) - strlen(alert_msg) - 1);
            }
        }
        
        if (critical_found > 0) {
            char full_msg[4096];
            char hostname[MAX_NAME];
            util_get_hostname(hostname, sizeof(hostname));
            
            snprintf(full_msg, sizeof(full_msg),
                    "SYSSEC Security Audit Alert\n"
                    "Host: %s\n"
                    "Time: %s\n"
                    "Critical Issues Found: %d\n"
                    "\n"
                    "%s",
                    hostname,
                    ctime(&(time_t){time(NULL)}),
                    critical_found,
                    alert_msg);
            
            if (alert_should_alert("security_audit", "critical", 
                                   config.alert_cooldown_hours)) {
                alert_send(config.alert_email, config.alert_command,
                          "SYSSEC: Critical Security Issues Found", full_msg);
            }
        }
    }
    
    /* Cleanup */
    log_close();
    report_free(&report);
    
    printf("\n" COLOR_GREEN "Done.\n" COLOR_RESET);
    return 0;
}
