/*
 * scanner.c - Core System Scanner for SYSSEC
 * 
 * This is the main scanning engine that collects system information
 * and detects security issues.
 * 
 * Compile: cc -Wall -Wextra -O2 -c scanner.c -o scanner.o
 */

#define __BSD_VISIBLE 1

#include "syssec.h"
#include "utils.h"
#include "logging.h"
#include "config.h"
#include "report.h"

/* ============================================================
 * DATA STRUCTURES
 * ============================================================ */

typedef struct {
    char name[128];
    char description[512];
    char recommendation[512];
    syssec_severity_t severity;
    syssec_status_t status;
    char category[64];
} scan_result_t;

#define MAX_RESULTS 512

typedef struct {
    scan_result_t results[MAX_RESULTS];
    int count;
    syssec_config_t config;
    char hostname[256];
    char kernel[512];
    time_t timestamp;
} scanner_state_t;

static scanner_state_t state;

/* ============================================================
 * INTERNAL: Add Result
 * ============================================================ */

static void add_result(const char *name, const char *desc, 
                       const char *rec, syssec_severity_t severity,
                       syssec_status_t status, const char *category) {
    if (state.count >= MAX_RESULTS) return;
    
    scan_result_t *r = &state.results[state.count];
    strncpy(r->name, name, sizeof(r->name) - 1);
    strncpy(r->description, desc, sizeof(r->description) - 1);
    strncpy(r->recommendation, rec, sizeof(r->recommendation) - 1);
    r->severity = severity;
    r->status = status;
    strncpy(r->category, category ? category : "General", sizeof(r->category) - 1);
    
    state.count++;
}

/* ============================================================
 * SCAN: System Information
 * ============================================================ */

void scan_system_info(void) {
    long physmem;
    int ncpu;
    char hostname[256];
    char kernel[512];
    char uptime_str[64];
    double load1, load5, load15;
    time_t uptime;
    
    /* Hostname */
    if (util_get_hostname(hostname, sizeof(hostname)) == SYSSEC_OK) {
        strncpy(state.hostname, hostname, sizeof(state.hostname) - 1);
    }
    
    /* Kernel */
    if (util_get_kernel_version(kernel, sizeof(kernel)) == SYSSEC_OK) {
        strncpy(state.kernel, kernel, sizeof(state.kernel) - 1);
    }
    
    /* CPU Count */
    if (util_get_num_cpus(&ncpu) == SYSSEC_OK) {
        char desc[512];
        snprintf(desc, sizeof(desc), "System has %d CPU cores", ncpu);
        add_result("CPU Count", desc, "", SEVERITY_INFO, STATUS_PASS, "System");
    }
    
    /* Memory */
    if (util_get_phys_memory(&physmem) == SYSSEC_OK) {
        char desc[512];
        snprintf(desc, sizeof(desc), "Total physical memory: %ld MB", 
                 physmem / (1024 * 1024));
        add_result("Physical Memory", desc, "", SEVERITY_INFO, STATUS_PASS, "System");
    }
    
    /* Uptime */
    if (util_get_uptime(&uptime) == SYSSEC_OK) {
        int days = uptime / 86400;
        int hours = (uptime % 86400) / 3600;
        int mins = (uptime % 3600) / 60;
        snprintf(uptime_str, sizeof(uptime_str), "%d days, %02d:%02d:%02d", 
                 days, hours, mins, (int)(uptime % 60));
        char desc[512];
        snprintf(desc, sizeof(desc), "System uptime: %s", uptime_str);
        add_result("System Uptime", desc, "", SEVERITY_INFO, STATUS_PASS, "System");
    }
    
    /* Load Average */
    if (util_get_load_avg(&load1, &load5, &load15) == SYSSEC_OK) {
        char desc[512];
        snprintf(desc, sizeof(desc), "Load averages: %.2f, %.2f, %.2f", 
                 load1, load5, load15);
        
        int status = STATUS_PASS;
        int ncpu_check;
        if (util_get_num_cpus(&ncpu_check) == SYSSEC_OK) {
            if (load1 > ncpu_check * 1.5) {
                status = STATUS_WARN;
            }
        }
        add_result("Load Average", desc, 
                  status == STATUS_WARN ? "High load average - check running processes" : "",
                  status == STATUS_WARN ? SEVERITY_WARNING : SEVERITY_INFO,
                  status, "System");
    }
}

/* ============================================================
 * SCAN: Running Processes
 * ============================================================ */

void scan_processes(void) {
    int count = util_get_process_count();
    if (count > 0) {
        char desc[512];
        snprintf(desc, sizeof(desc), "Total running processes: %d", count);
        
        int status = STATUS_PASS;
        char rec[256] = {0};
        
        /* Check for excessive processes */
        if (count > 500) {
            status = STATUS_WARN;
            snprintf(rec, sizeof(rec), "High process count - check for runaway processes");
        }
        
        add_result("Process Count", desc, rec,
                  status == STATUS_WARN ? SEVERITY_WARNING : SEVERITY_INFO,
                  status, "Processes");
    }
}

/* ============================================================
 * SCAN: User Accounts
 * ============================================================ */

void scan_users(void) {
    struct passwd *pw;
    int total_users = 0;
    int root_users = 0;
    int users_with_shell = 0;
    char bad_users[1024] = {0};
    
    setpwent();
    while ((pw = getpwent()) != NULL) {
        total_users++;
        
        if (pw->pw_uid == 0 && strcmp(pw->pw_name, "root") != 0) {
            root_users++;
            if (bad_users[0]) {
                strncat(bad_users, ", ", sizeof(bad_users) - strlen(bad_users) - 1);
            }
            strncat(bad_users, pw->pw_name, sizeof(bad_users) - strlen(bad_users) - 1);
        }
        
        if (strcmp(pw->pw_shell, "/sbin/nologin") != 0 &&
            strcmp(pw->pw_shell, "/usr/sbin/nologin") != 0 &&
            strcmp(pw->pw_shell, "/bin/false") != 0) {
            users_with_shell++;
        }
    }
    endpwent();
    
    char desc[512];
    snprintf(desc, sizeof(desc), "Total users: %d, users with valid shell: %d", 
             total_users, users_with_shell);
    add_result("User Accounts", desc, "", SEVERITY_INFO, STATUS_PASS, "Users");
    
    if (root_users > 0) {
        char rec[512];
        snprintf(rec, sizeof(rec), "Remove additional UID 0 users: %s", bad_users);
        add_result("UID 0 Users", "Additional users with root privileges found",
                  rec, SEVERITY_CRITICAL, STATUS_FAIL, "Security");
    }
}

/* ============================================================
 * SCAN: Filesystem
 * ============================================================ */

void scan_filesystem(void) {
    const struct {
        const char *path;
        mode_t expected;
        const char *name;
    } critical_files[] = {
        {"/etc/passwd", 0644, "Passwd file"},
        {"/etc/master.passwd", 0600, "Master passwd"},
        {"/etc/group", 0644, "Group file"},
        {"/etc/sudoers", 0440, "Sudoers file"},
        {NULL, 0, NULL}
    };
    
    for (int i = 0; critical_files[i].path != NULL; i++) {
        struct stat st;
        if (stat(critical_files[i].path, &st) < 0) {
            char desc[512];
            snprintf(desc, sizeof(desc), "%s does not exist", critical_files[i].path);
            add_result(critical_files[i].name, desc,
                      "File should exist with proper permissions",
                      SEVERITY_CRITICAL, STATUS_FAIL, "Filesystem");
            continue;
        }
        
        mode_t mode = st.st_mode & 0777;
        char desc[512];
        snprintf(desc, sizeof(desc), "%s permissions: %03o", critical_files[i].path, mode);
        
        int status = STATUS_PASS;
        if (mode != critical_files[i].expected) {
            status = (st.st_mode & S_IWOTH) ? STATUS_FAIL : STATUS_WARN;
        }
        
        char rec[512];
        if (status != STATUS_PASS) {
            snprintf(rec, sizeof(rec), "Set permissions to %03o", critical_files[i].expected);
        } else {
            rec[0] = '\0';
        }
        
        add_result(critical_files[i].name, desc, rec,
                  status == STATUS_FAIL ? SEVERITY_CRITICAL : 
                  status == STATUS_WARN ? SEVERITY_WARNING : SEVERITY_INFO,
                  status, "Filesystem");
    }
}

/* ============================================================
 * SCAN: Network
 * ============================================================ */

void scan_network(void) {
    /* Check listening ports */
    FILE *fp = popen("sockstat -4 -l 2>/dev/null | grep -v '^USER' | wc -l", "r");
    if (fp) {
        char buf[128];
        if (fgets(buf, sizeof(buf), fp)) {
            int ports = atoi(buf);
            char desc[512];
            snprintf(desc, sizeof(desc), "Listening ports: %d", ports);
            
            int status = STATUS_PASS;
            char rec[256] = {0};
            if (ports > 20) {
                status = STATUS_WARN;
                snprintf(rec, sizeof(rec), "Many listening ports - review with 'sockstat -4 -l'");
            }
            add_result("Listening Ports", desc, rec,
                      status == STATUS_WARN ? SEVERITY_WARNING : SEVERITY_INFO,
                      status, "Network");
        }
        pclose(fp);
    }
    
    /* Check SSH status */
    if (util_process_running("sshd")) {
        add_result("SSH Server", "SSH daemon is running",
                  "Keep SSH secure with proper configuration",
                  SEVERITY_INFO, STATUS_PASS, "Network");
    }
}

/* ============================================================
 * SCAN: Services
 * ============================================================ */

void scan_services(void) {
    const char *critical_services[] = {
        "syslogd",
        "cron",
        "sshd",
        NULL
    };
    
    for (int i = 0; critical_services[i] != NULL; i++) {
        int running = util_process_running(critical_services[i]);
        char desc[512];
        snprintf(desc, sizeof(desc), "Service '%s' is %s", 
                 critical_services[i], running ? "running" : "STOPPED");
        
        int status = running ? STATUS_PASS : STATUS_FAIL;
        char rec[256] = {0};
        if (!running) {
            snprintf(rec, sizeof(rec), "Start service: service %s start", critical_services[i]);
        }
        
        add_result(critical_services[i], desc, rec,
                  status == STATUS_FAIL ? SEVERITY_CRITICAL : SEVERITY_INFO,
                  status, "Services");
    }
}

/* ============================================================
 * SCAN: Security Settings
 * ============================================================ */

void scan_security(void) {
    /* Check securelevel */
    int securelevel;
    size_t len = sizeof(securelevel);
    if (sysctlbyname("kern.securelevel", &securelevel, &len, NULL, 0) == 0) {
        char desc[512];
        snprintf(desc, sizeof(desc), "Securelevel: %d", securelevel);
        
        int status = STATUS_PASS;
        char rec[256] = {0};
        if (securelevel == 0) {
            status = STATUS_WARN;
            snprintf(rec, sizeof(rec), "Set kern.securelevel=1 in /etc/sysctl.conf");
        }
        add_result("Kernel Securelevel", desc, rec,
                  status == STATUS_WARN ? SEVERITY_WARNING : SEVERITY_INFO,
                  status, "Security");
    }
    
    /* Check IP forwarding */
    int ip_forward;
    len = sizeof(ip_forward);
    if (sysctlbyname("net.inet.ip.forwarding", &ip_forward, &len, NULL, 0) == 0) {
        if (ip_forward) {
            add_result("IP Forwarding", "IP forwarding is ENABLED",
                      "Disable if not a router: set net.inet.ip.forwarding=0",
                      SEVERITY_WARNING, STATUS_WARN, "Security");
        }
    }
}

/* ============================================================
 * SCAN: Logs
 * ============================================================ */

void scan_logs(void) {
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
        add_result("System Logs", "Some log files are missing",
                  "Configure syslogd properly", SEVERITY_WARNING, STATUS_WARN, "Logging");
    } else {
        add_result("System Logs", "Log files are present",
                  "", SEVERITY_INFO, STATUS_PASS, "Logging");
    }
}

/* ============================================================
 * SCAN: Updates
 * ============================================================ */

void scan_updates(void) {
    if (util_file_exists("/usr/sbin/freebsd-update")) {
        add_result("Update System", "freebsd-update is installed",
                  "Run: freebsd-update fetch install", SEVERITY_INFO, STATUS_PASS, "Updates");
    } else {
        add_result("Update System", "freebsd-update is not installed",
                  "Install or use ports for updates", SEVERITY_WARNING, STATUS_WARN, "Updates");
    }
}

/* ============================================================
 * SCAN: TTY Security
 * ============================================================ */

void scan_ttys(void) {
    if (!util_file_exists("/proc")) {
        add_result("TTY Scan", "/proc is not mounted",
                  "Mount /proc: mount -t procfs proc /proc",
                  SEVERITY_WARNING, STATUS_WARN, "Security");
        return;
    }
    
    /* Scan for suspicious TTYs */
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;
    
    struct dirent *entry;
    int found = 0;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        
        int pid = atoi(entry->d_name);
        char fd_path[512];
        char link[512];
        
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd/0", entry->d_name);
        ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
        
        if (len > 0) {
            link[len] = '\0';
            if (strncmp(link, "/dev/tty", 8) == 0 ||
                strncmp(link, "/dev/pts/", 9) == 0) {
                /* Check if login exists */
                const char *tty = strrchr(link, '/');
                if (tty) tty++;
                else tty = link;
                
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "who | grep -q '%s'", tty);
                if (system(cmd) != 0) {
                    found++;
                    if (found == 1) {
                        add_result("Suspicious TTYs", 
                                  "TTYs active without login sessions found",
                                  "Check for potential backdoors",
                                  SEVERITY_WARNING, STATUS_WARN, "Security");
                    }
                }
            }
        }
    }
    closedir(proc_dir);
}

/* ============================================================
 * PUBLIC: scanner_init
 * ============================================================ */

syssec_error_t scanner_init(syssec_config_t *config) {
    if (!config) {
        return SYSSEC_ERR_INVALID;
    }
    
    memset(&state, 0, sizeof(state));
    memcpy(&state.config, config, sizeof(syssec_config_t));
    state.timestamp = time(NULL);
    
    util_get_hostname(state.hostname, sizeof(state.hostname));
    util_get_kernel_version(state.kernel, sizeof(state.kernel));
    
    return SYSSEC_OK;
}

/* ============================================================
 * PUBLIC: scanner_run
 * ============================================================ */

syssec_error_t scanner_run(void) {
    log_info("Starting system scan on %s", state.hostname);
    
    scan_system_info();
    scan_processes();
    scan_users();
    scan_filesystem();
    scan_network();
    scan_services();
    scan_security();
    scan_logs();
    scan_updates();
    scan_ttys();
    
    log_info("Scan complete: %d checks performed", state.count);
    return SYSSEC_OK;
}

/* ============================================================
 * PUBLIC: scanner_get_results
 * ============================================================ */

int scanner_get_results(void) {
    return state.count;
}

/* ============================================================
 * PUBLIC: scanner_export_to_report
 * ============================================================ */

syssec_error_t scanner_export_to_report(syssec_report_t *report) {
    if (!report) {
        return SYSSEC_ERR_INVALID;
    }
    
    report_init(report);
    
    for (int i = 0; i < state.count; i++) {
        syssec_report_entry_t entry;
        strncpy(entry.name, state.results[i].name, sizeof(entry.name) - 1);
        entry.status = state.results[i].status;
        entry.severity = state.results[i].severity;
        strncpy(entry.message, state.results[i].description, sizeof(entry.message) - 1);
        strncpy(entry.recommendation, state.results[i].recommendation, 
                sizeof(entry.recommendation) - 1);
        strncpy(entry.category, state.results[i].category, sizeof(entry.category) - 1);
        report_add_entry(report, &entry);
    }
    
    return SYSSEC_OK;
}

/* ============================================================
 * PUBLIC: scanner_print_summary
 * ============================================================ */

void scanner_print_summary(void) {
    int passed = 0, warnings = 0, failed = 0;
    
    for (int i = 0; i < state.count; i++) {
        switch (state.results[i].status) {
            case STATUS_PASS: passed++; break;
            case STATUS_WARN: warnings++; break;
            case STATUS_FAIL: failed++; break;
            default: break;
        }
    }
    
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    SCAN SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    printf("  Host:   %s\n", state.hostname);
    printf("  Kernel: %s\n", state.kernel);
    printf("  Time:   %s", ctime(&state.timestamp));
    printf("\n");
    printf("  %sPassed:%s  %d\n", COLOR_GREEN, COLOR_RESET, passed);
    printf("  %sWarnings:%s %d\n", COLOR_YELLOW, COLOR_RESET, warnings);
    printf("  %sFailed:%s  %d\n", COLOR_RED, COLOR_RESET, failed);
    printf("  %sTotal:%s   %d\n", COLOR_BOLD, COLOR_RESET, state.count);
    
    if (failed > 0) {
        printf("\n" COLOR_RED "  ⚠ %d CRITICAL issues found!\n" COLOR_RESET, failed);
        printf(COLOR_RED "  Address these immediately.\n" COLOR_RESET);
    } else if (warnings > 0) {
        printf("\n" COLOR_YELLOW "  ⚠ %d warnings found\n" COLOR_RESET, warnings);
    } else {
        printf("\n" COLOR_GREEN "  ✓ All checks passed!\n" COLOR_RESET);
    }
}

/* ============================================================
 * PUBLIC: scanner_print_results
 * ============================================================ */

void scanner_print_results(void) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    DETAILED RESULTS\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    
    for (int i = 0; i < state.count; i++) {
        scan_result_t *r = &state.results[i];
        const char *color = syssec_status_color(r->status);
        
        printf("  %s[%s]%s %s\n",
               color,
               syssec_status_str(r->status),
               COLOR_RESET,
               r->name);
        printf("    %s\n", r->description);
        if (r->recommendation[0] != '\0' && r->status != STATUS_PASS) {
            printf("    " COLOR_YELLOW "→ %s" COLOR_RESET "\n", r->recommendation);
        }
        printf("\n");
    }
}

/* ============================================================
 * PUBLIC: scanner_cleanup
 * ============================================================ */

void scanner_cleanup(void) {
    /* Nothing to free currently, but keep for future */
}

/* ============================================================
 * PUBLIC: scanner_get_hostname
 * ============================================================ */

const char* scanner_get_hostname(void) {
    return state.hostname;
}

/* ============================================================
 * PUBLIC: scanner_get_kernel
 * ============================================================ */

const char* scanner_get_kernel(void) {
    return state.kernel;
}
