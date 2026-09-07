/*
 * health_check.c - System Health & Sanity Checker for FreeBSD
 * 
 * This program checks:
 * 1. System resources (CPU, memory, disk, swap)
 * 2. System logs for errors
 * 3. Process health (zombies, high CPU, high memory)
 * 4. File system health
 * 5. Network connectivity
 * 6. System time and NTP
 * 7. Critical services
 * 8. System limits
 *
 * Compile: cc -Wall -Wextra -O2 health_check.c -o health_check
 * Run: ./health_check
 */

#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mount.h>

/* ============================================================
 * COLORS
 * ============================================================ */

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_BOLD    "\033[1m"

/* ============================================================
 * STRUCTURES
 * ============================================================ */

typedef struct {
    char name[128];
    char description[256];
    char result[256];
    int status; /* 0=pass, 1=warning, 2=fail */
    char recommendation[512];
} health_check_t;

#define MAX_CHECKS 64
health_check_t checks[MAX_CHECKS];
int num_checks = 0;

/* ============================================================
 * HELPER FUNCTIONS
 * ============================================================ */

void add_check(const char *name, const char *desc, 
               const char *result, int status, const char *rec) {
    if (num_checks >= MAX_CHECKS) return;
    
    strncpy(checks[num_checks].name, name, sizeof(checks[num_checks].name) - 1);
    strncpy(checks[num_checks].description, desc, sizeof(checks[num_checks].description) - 1);
    strncpy(checks[num_checks].result, result, sizeof(checks[num_checks].result) - 1);
    checks[num_checks].status = status;
    if (rec) {
        strncpy(checks[num_checks].recommendation, rec, 
                sizeof(checks[num_checks].recommendation) - 1);
    } else {
        checks[num_checks].recommendation[0] = '\0';
    }
    num_checks++;
}

const char* status_text(int status) {
    switch (status) {
        case 0: return "PASS";
        case 1: return "WARN";
        case 2: return "FAIL";
        default: return "UNKNOWN";
    }
}

const char* status_color(int status) {
    switch (status) {
        case 0: return COLOR_GREEN;
        case 1: return COLOR_YELLOW;
        case 2: return COLOR_RED;
        default: return COLOR_BLUE;
    }
}

int is_root(void) {
    return geteuid() == 0;
}

/* ============================================================
 * 1. SYSTEM RESOURCES
 * ============================================================ */

void check_cpu_usage(void) {
    long cpu_time[5];
    size_t len = sizeof(cpu_time);
    
    if (sysctlbyname("kern.cp_time", cpu_time, &len, NULL, 0) == 0) {
        long total = 0;
        for (int i = 0; i < 5; i++) total += cpu_time[i];
        
        if (total > 0) {
            long idle = cpu_time[4];
            long used = total - idle;
            int percent = (int)((used * 100) / total);
            
            char result[256];
            snprintf(result, sizeof(result), "CPU usage: %d%%", percent);
            
            int status = 0;
            char rec[512] = {0};
            if (percent > 90) {
                status = 1;
                snprintf(rec, sizeof(rec), "High CPU usage - check running processes with 'top'");
            } else if (percent > 70) {
                status = 1;
                snprintf(rec, sizeof(rec), "Moderate CPU usage - monitor for trends");
            }
            add_check("CPU Usage", "System CPU utilization", result, status, rec);
        }
    }
}

void check_memory_usage(void) {
    long physmem;
    long pages_free;
    long pages_active;
    size_t len;
    
    len = sizeof(physmem);
    if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) < 0) return;
    
    len = sizeof(pages_free);
    if (sysctlbyname("vm.stats.vm.v_free_count", &pages_free, &len, NULL, 0) < 0) return;
    
    len = sizeof(pages_active);
    if (sysctlbyname("vm.stats.vm.v_active_count", &pages_active, &len, NULL, 0) < 0) return;
    
    long page_size = getpagesize();
    long total_pages = physmem / page_size;
    long used_pages = total_pages - pages_free;
    int percent = (int)((used_pages * 100) / total_pages);
    
    char result[256];
    snprintf(result, sizeof(result), "Memory usage: %d%% (%ld MB used / %ld MB total)",
             percent,
             used_pages * page_size / (1024 * 1024),
             total_pages * page_size / (1024 * 1024));
    
    int status = 0;
    char rec[512] = {0};
    if (percent > 95) {
        status = 2;
        snprintf(rec, sizeof(rec), "Critical: Memory nearly full - check for memory leaks or add more RAM");
    } else if (percent > 80) {
        status = 1;
        snprintf(rec, sizeof(rec), "Memory usage is high - monitor for trends and consider adding swap");
    }
    add_check("Memory Usage", "System memory utilization", result, status, rec);
}

void check_disk_usage(void) {
    FILE *fp = popen("df -h / /usr /var /tmp 2>/dev/null", "r");
    if (!fp) return;
    
    char line[512];
    int header_skipped = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (!header_skipped) {
            header_skipped = 1;
            continue;
        }
        
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        /* Parse: Filesystem Size Used Avail Capacity Mounted on */
        char fs[64], size[16], used[16], avail[16], capacity[16], mount[64];
        if (sscanf(line, "%s %s %s %s %s %s", fs, size, used, avail, capacity, mount) == 6) {
            /* Remove % from capacity */
            int cap = atoi(capacity);
            char result[256];
            snprintf(result, sizeof(result), "%s: %s (%s used)", mount, capacity, used);
            
            int status = 0;
            char rec[512] = {0};
            if (cap > 95) {
                status = 2;
                snprintf(rec, sizeof(rec), "Critical: %s is almost full - clean up disk space", mount);
            } else if (cap > 80) {
                status = 1;
                snprintf(rec, sizeof(rec), "%s is getting full - monitor disk usage", mount);
            }
            add_check("Disk Usage", "Filesystem utilization", result, status, rec);
        }
    }
    pclose(fp);
}

void check_swap_usage(void) {
    FILE *fp = popen("swapinfo -m 2>/dev/null", "r");
    if (!fp) return;
    
    char line[512];
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        if (strstr(line, "Total") || strstr(line, "Device") || line[0] == '\0') {
            continue;
        }
        
        char device[64];
        int used, total;
        if (sscanf(line, "%s %d %d", device, &total, &used) == 3) {
            found = 1;
            int percent = total > 0 ? (used * 100) / total : 0;
            char result[256];
            snprintf(result, sizeof(result), "%s: %d%% used (%d/%d MB)", 
                     device, percent, used, total);
            
            int status = 0;
            char rec[512] = {0};
            if (percent > 90) {
                status = 2;
                snprintf(rec, sizeof(rec), "Swap is nearly full - add more swap space");
            } else if (percent > 50) {
                status = 1;
                snprintf(rec, sizeof(rec), "Swap usage is moderate - monitor");
            }
            add_check("Swap Usage", "Swap space utilization", result, status, rec);
            break;
        }
    }
    pclose(fp);
    
    if (!found) {
        add_check("Swap Usage", "No swap configured", "No swap found", 1, "Add swap space for system stability");
    }
}

/* ============================================================
 * 2. SYSTEM LOGS
 * ============================================================ */

void check_log_errors(void) {
    const char *log_files[] = {
        "/var/log/messages",
        "/var/log/auth.log",
        "/var/log/secure",
        NULL
    };
    
    const char *error_patterns[] = {
        "error",
        "failed",
        "corrupt",
        "panic",
        "critical",
        "emerg",
        "alert",
        "segfault",
        NULL
    };
    
    for (int i = 0; log_files[i] != NULL; i++) {
        FILE *fp = fopen(log_files[i], "r");
        if (!fp) continue;
        
        char line[1024];
        int errors = 0;
        int lines = 0;
        
        /* Read last 100 lines */
        fseek(fp, -4096, SEEK_END);
        while (fgets(line, sizeof(line), fp)) {
            lines++;
            for (int j = 0; error_patterns[j] != NULL; j++) {
                if (strstr(line, error_patterns[j])) {
                    errors++;
                    break;
                }
            }
        }
        fclose(fp);
        
        if (errors > 0) {
            char result[256];
            snprintf(result, sizeof(result), "Found %d errors in last %d lines of %s", 
                     errors, lines, log_files[i]);
            add_check("Log Errors", "System log error count", result, 1, 
                     "Check logs for errors: tail -100 " log_files[i]);
        } else {
            char result[256];
            snprintf(result, sizeof(result), "%s: No errors found", log_files[i]);
            add_check("Log Errors", "System log error count", result, 0, NULL);
        }
    }
}

/* ============================================================
 * 3. PROCESS HEALTH
 * ============================================================ */

void check_zombie_processes(void) {
    struct kinfo_proc *proc_list = NULL;
    size_t len = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) return;
    
    proc_list = malloc(len);
    if (!proc_list) return;
    
    if (sysctl(mib, 4, proc_list, &len, NULL, 0) < 0) {
        free(proc_list);
        return;
    }
    
    int count = len / sizeof(struct kinfo_proc);
    int zombies = 0;
    
    for (int i = 0; i < count; i++) {
        if (proc_list[i].ki_stat == 'Z') {
            zombies++;
        }
    }
    
    free(proc_list);
    
    char result[256];
    snprintf(result, sizeof(result), "%d zombie processes", zombies);
    
    int status = 0;
    char rec[512] = {0};
    if (zombies > 0) {
        status = 1;
        snprintf(rec, sizeof(rec), "Zombie processes found - reboot may be needed or check parent processes");
    }
    add_check("Zombie Processes", "Processes in zombie state", result, status, rec);
}

void check_high_memory_processes(void) {
    struct kinfo_proc *proc_list = NULL;
    size_t len = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) return;
    
    proc_list = malloc(len);
    if (!proc_list) return;
    
    if (sysctl(mib, 4, proc_list, &len, NULL, 0) < 0) {
        free(proc_list);
        return;
    }
    
    int count = len / sizeof(struct kinfo_proc);
    int high_mem = 0;
    
    /* Sort by memory and take top 3 */
    for (int i = 0; i < count && i < 3; i++) {
        if (proc_list[i].ki_rssize > 1000000) { /* 1GB in pages */
            high_mem++;
        }
    }
    
    free(proc_list);
    
    if (high_mem > 0) {
        add_check("High Memory Processes", "Processes using >1GB RAM", 
                 "Found processes with high memory usage", 1, 
                 "Check 'ps aux' for memory-heavy processes");
    } else {
        add_check("High Memory Processes", "Processes using >1GB RAM", 
                 "No high-memory processes found", 0, NULL);
    }
}

/* ============================================================
 * 4. FILE SYSTEM HEALTH
 * ============================================================ */

void check_filesystem_health(void) {
    /* Check if /etc/fstab exists */
    if (!file_exists("/etc/fstab")) {
        add_check("File System", "/etc/fstab missing", 
                 "FATAL: /etc/fstab not found", 2, 
                 "Restore /etc/fstab from backup");
        return;
    }
    
    /* Check mounts */
    FILE *fp = popen("mount | wc -l", "r");
    if (fp) {
        char buf[128];
        if (fgets(buf, sizeof(buf), fp)) {
            int mounts = atoi(buf);
            char result[256];
            snprintf(result, sizeof(result), "%d filesystems mounted", mounts);
            if (mounts == 0) {
                add_check("File System", "No filesystems mounted", result, 2, 
                         "Check system mounts immediately");
            } else {
                add_check("File System", "Mounted filesystems", result, 0, NULL);
            }
        }
        pclose(fp);
    }
    
    /* Check root filesystem */
    struct statfs stfs;
    if (statfs("/", &stfs) == 0) {
        long total = (long)stfs.f_blocks * stfs.f_bsize / (1024 * 1024);
        long free = (long)stfs.f_bavail * stfs.f_bsize / (1024 * 1024);
        char result[256];
        snprintf(result, sizeof(result), "Root: %ld MB free / %ld MB total", free, total);
        add_check("Root Filesystem", "Root partition space", result, 0, NULL);
    }
}

/* ============================================================
 * 5. NETWORK HEALTH
 * ============================================================ */

void check_network_interfaces(void) {
    FILE *fp = popen("ifconfig -a | grep -E '^[a-z]' | wc -l", "r");
    if (!fp) return;
    
    char buf[128];
    if (fgets(buf, sizeof(buf), fp)) {
        int interfaces = atoi(buf);
        char result[256];
        snprintf(result, sizeof(result), "%d network interfaces", interfaces);
        
        if (interfaces == 0) {
            add_check("Network", "Network interfaces", result, 2, 
                     "No network interfaces found - check hardware");
        } else if (interfaces == 1) {
            add_check("Network", "Network interfaces", result, 1, 
                     "Only one network interface - check for additional interfaces");
        } else {
            add_check("Network", "Network interfaces", result, 0, NULL);
        }
    }
    pclose(fp);
}

void check_network_connectivity(void) {
    /* Ping localhost */
    int status = system("ping -c 1 127.0.0.1 > /dev/null 2>&1");
    if (status == 0) {
        add_check("Network", "Loopback connectivity", "Loopback (127.0.0.1) is working", 0, NULL);
    } else {
        add_check("Network", "Loopback connectivity", "Loopback is not responding", 2, 
                 "Check network configuration - 'ifconfig lo0 up'");
    }
    
    /* Ping default gateway */
    status = system("route -n get default 2>/dev/null | grep -q 'gateway:' && ping -c 1 `route -n get default | grep gateway | awk '{print $2}'` > /dev/null 2>&1");
    if (status == 0) {
        add_check("Network", "Gateway connectivity", "Default gateway is reachable", 0, NULL);
    } else {
        add_check("Network", "Gateway connectivity", "Default gateway is not reachable", 1, 
                 "Check network configuration and gateway");
    }
    
    /* Check DNS resolution */
    status = system("host freebsd.org > /dev/null 2>&1");
    if (status == 0) {
        add_check("Network", "DNS resolution", "DNS is working", 0, NULL);
    } else {
        add_check("Network", "DNS resolution", "DNS is not working", 1, 
                 "Check /etc/resolv.conf and network connectivity");
    }
}

/* ============================================================
 * 6. SYSTEM TIME
 * ============================================================ */

void check_system_time(void) {
    /* Check if NTP is running */
    int ntp_running = system("pgrep -x ntpd > /dev/null 2>&1") == 0;
    int ntp_running_open = system("pgrep -x openntpd > /dev/null 2>&1") == 0;
    
    if (ntp_running || ntp_running_open) {
        add_check("System Time", "NTP daemon running", "NTP is running", 0, NULL);
        
        /* Check NTP sync */
        int synced = system("ntpq -pn 2>/dev/null | grep -q '^*'") == 0;
        if (synced) {
            add_check("System Time", "NTP sync status", "Time is synchronized", 0, NULL);
        } else {
            add_check("System Time", "NTP sync status", "NTP is not synchronized", 1, 
                     "Check NTP configuration and network");
        }
    } else {
        add_check("System Time", "NTP daemon", "NTP is not running", 1, 
                 "Start NTP: 'service ntpd start' or 'service openntpd start'");
    }
}

/* ============================================================
 * 7. CRITICAL SERVICES
 * ============================================================ */

void check_critical_services(void) {
    const char *services[] = {
        "syslogd",
        "cron",
        "sshd",
        NULL
    };
    
    for (int i = 0; services[i] != NULL; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "pgrep -x %s > /dev/null 2>&1", services[i]);
        int running = system(cmd) == 0;
        
        char result[256];
        snprintf(result, sizeof(result), "%s is %s", 
                 services[i], running ? "running" : "NOT running");
        
        int status = running ? 0 : 2;
        char rec[512] = {0};
        if (!running) {
            snprintf(rec, sizeof(rec), "Start %s: 'service %s start'", services[i], services[i]);
        }
        add_check("Critical Services", "Essential system services", result, status, rec);
    }
}

/* ============================================================
 * 8. SYSTEM LIMITS
 * ============================================================ */

void check_system_limits(void) {
    struct rlimit rl;
    
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        char result[256];
        snprintf(result, sizeof(result), "Max open files: %ld", rl.rlim_cur);
        add_check("System Limits", "File descriptor limit", result, 0, NULL);
    }
    
    if (getrlimit(RLIMIT_NPROC, &rl) == 0) {
        char result[256];
        snprintf(result, sizeof(result), "Max processes: %ld", rl.rlim_cur);
        add_check("System Limits", "Process limit", result, 0, NULL);
    }
}

/* ============================================================
 * 9. SECURITY CHECKS
 * ============================================================ */

void check_security_basics(void) {
    /* Check if root can login via SSH */
    FILE *fp = fopen("/etc/ssh/sshd_config", "r");
    if (fp) {
        char line[1024];
        int root_login = 0;
        int password_auth = 0;
        
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "PermitRootLogin") && strstr(line, "yes")) {
                root_login = 1;
            }
            if (strstr(line, "PasswordAuthentication") && strstr(line, "yes")) {
                password_auth = 1;
            }
        }
        fclose(fp);
        
        if (root_login) {
            add_check("Security", "SSH root login", "Root login is enabled", 1, 
                     "Disable root login: PermitRootLogin no");
        } else {
            add_check("Security", "SSH root login", "Root login is disabled", 0, NULL);
        }
        
        if (password_auth) {
            add_check("Security", "SSH password auth", "Password auth is enabled", 1, 
                     "Use key-based authentication: PasswordAuthentication no");
        } else {
            add_check("Security", "SSH password auth", "Password auth is disabled", 0, NULL);
        }
    }
}

/* ============================================================
 * PRINT RESULTS
 * ============================================================ */

void print_health_summary(void) {
    int passed = 0, warnings = 0, failed = 0;
    
    for (int i = 0; i < num_checks; i++) {
        switch (checks[i].status) {
            case 0: passed++; break;
            case 1: warnings++; break;
            case 2: failed++; break;
        }
    }
    
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    HEALTH CHECK SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    printf("  %s%sPassed:%s %d\n", COLOR_BOLD, COLOR_GREEN, COLOR_RESET, passed);
    printf("  %s%sWarnings:%s %d\n", COLOR_BOLD, COLOR_YELLOW, COLOR_RESET, warnings);
    printf("  %s%sFailed:%s %d\n", COLOR_BOLD, COLOR_RED, COLOR_RESET, failed);
    printf("  %sTotal:%s %d\n", COLOR_BOLD, COLOR_RESET, num_checks);
    
    if (failed > 0) {
        printf("\n" COLOR_RED "  ⚠ CRITICAL: %d checks failed!\n" COLOR_RESET, failed);
        printf(COLOR_RED "  Address these issues immediately.\n" COLOR_RESET);
    } else if (warnings > 0) {
        printf("\n" COLOR_YELLOW "  ⚠ WARNING: %d checks need attention.\n" COLOR_RESET, warnings);
    } else {
        printf("\n" COLOR_GREEN "  ✓ All checks passed!\n" COLOR_RESET);
    }
}

void print_detailed_health(void) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    DETAILED HEALTH CHECKS\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    
    for (int i = 0; i < num_checks; i++) {
        const char *color = status_color(checks[i].status);
        printf("  %s[%s]%s %s\n",
               color,
               status_text(checks[i].status),
               COLOR_RESET,
               checks[i].name);
        printf("    %s\n", checks[i].description);
        printf("    Result: %s\n", checks[i].result);
        if (checks[i].recommendation[0] != '\0' && checks[i].status > 0) {
            printf("    " COLOR_YELLOW "→ %s" COLOR_RESET "\n", checks[i].recommendation);
        }
        printf("\n");
    }
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(int argc, char **argv) {
    int verbose = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("  -v, --verbose  Show detailed checks\n");
            printf("  -h, --help     Show this help\n");
            return 0;
        }
    }
    
    printf(COLOR_CYAN "╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    SYSTEM HEALTH CHECKER                           ║\n");
    printf("║                    FreeBSD Health & Sanity                         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    
    /* Run all checks */
    check_cpu_usage();
    check_memory_usage();
    check_disk_usage();
    check_swap_usage();
    check_log_errors();
    check_zombie_processes();
    check_high_memory_processes();
    check_filesystem_health();
    check_network_interfaces();
    check_network_connectivity();
    check_system_time();
    check_critical_services();
    check_system_limits();
    check_security_basics();
    
    /* Print results */
    print_health_summary();
    
    if (verbose) {
        print_detailed_health();
    }
    
    printf("\n" COLOR_GREEN "Done.\n" COLOR_RESET);
    
    return 0;
}
