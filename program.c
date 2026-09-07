/*
 * sysinfo.c - System Information Tool with Security Checks for FreeBSD
 * 
 * This program demonstrates:
 * 1. Reading /proc for process information
 * 2. Reading /dev for device information
 * 3. Using sysctl for kernel information
 * 4. Detecting TTYs and their usage
 * 5. Finding suspicious configuration files
 * 6. Detecting unauthorized SUID/SGID binaries
 * 7. Checking for unusual system files
 *
 * Compile: cc -Wall -Wextra -O2 sysinfo.c -o sysinfo
 * Run: ./sysinfo
 */

#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

/* ============================================================
 * COLORS FOR TERMINAL OUTPUT
 * ============================================================ */

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

/* ============================================================
 * DATA STRUCTURES
 * ============================================================ */

typedef struct {
    char path[512];
    char expected_content[256];
    char finding[512];
    int severity; /* 0=info, 1=warning, 2=critical */
} security_finding_t;

#define MAX_FINDINGS 256
security_finding_t findings[MAX_FINDINGS];
int num_findings = 0;

/* ============================================================
 * UTILITY FUNCTIONS
 * ============================================================ */

/* Check if /proc is mounted */
int is_proc_mounted(void) {
    FILE *fp = fopen("/proc/curproc/status", "r");
    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

/* Get current username */
const char* get_username(void) {
    struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_name : "unknown";
}

/* Format time as string */
void format_time(time_t t, char *buf, size_t size) {
    struct tm *tm = localtime(&t);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm);
}

/* Add a finding */
void add_finding(const char *path, const char *finding, int severity, const char *expected) {
    if (num_findings >= MAX_FINDINGS) return;
    
    strncpy(findings[num_findings].path, path, sizeof(findings[num_findings].path) - 1);
    findings[num_findings].path[sizeof(findings[num_findings].path) - 1] = '\0';
    
    strncpy(findings[num_findings].finding, finding, sizeof(findings[num_findings].finding) - 1);
    findings[num_findings].finding[sizeof(findings[num_findings].finding) - 1] = '\0';
    
    findings[num_findings].severity = severity;
    
    if (expected) {
        strncpy(findings[num_findings].expected_content, expected, 
                sizeof(findings[num_findings].expected_content) - 1);
        findings[num_findings].expected_content[sizeof(findings[num_findings].expected_content) - 1] = '\0';
    } else {
        findings[num_findings].expected_content[0] = '\0';
    }
    
    num_findings++;
}

/* ============================================================
 * SYSTEM INFORMATION (from previous version)
 * ============================================================ */

void print_system_info(void) {
    char buf[256];
    size_t len;
    long boot_time;
    int ncpu;
    char model[256];
    long physmem;
    
    printf("\n" COLOR_BOLD "=== SYSTEM INFORMATION ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    len = sizeof(buf);
    if (sysctlbyname("kern.hostname", buf, &len, NULL, 0) == 0) {
        printf("  Hostname:   %s\n", buf);
    }
    
    len = sizeof(buf);
    if (sysctlbyname("kern.osrelease", buf, &len, NULL, 0) == 0) {
        printf("  OS Release: %s\n", buf);
    }
    
    len = sizeof(buf);
    if (sysctlbyname("kern.version", buf, &len, NULL, 0) == 0) {
        printf("  Kernel:     %s\n", buf);
    }
    
    len = sizeof(model);
    if (sysctlbyname("hw.model", model, &len, NULL, 0) == 0) {
        printf("  CPU:        %s\n", model);
    }
    
    len = sizeof(ncpu);
    if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0) {
        printf("  Cores:      %d\n", ncpu);
    }
    
    len = sizeof(physmem);
    if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) == 0) {
        printf("  Memory:     %ld MB\n", physmem / (1024 * 1024));
    }
    
    len = sizeof(boot_time);
    if (sysctlbyname("kern.boottime", &boot_time, &len, NULL, 0) == 0) {
        char timebuf[64];
        format_time(boot_time, timebuf, sizeof(timebuf));
        printf("  Boot Time:  %s\n", timebuf);
    }
    
    printf("  User:       %s\n", get_username());
    
    FILE *fp = popen("uptime", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            printf("  Uptime:     %s\n", line);
        }
        pclose(fp);
    }
}

/* ============================================================
 * SECURITY CHECKS
 * ============================================================ */

/* Check suspicious files in /etc/ */
void check_etc_files(void) {
    const char *suspicious_files[] = {
        "/etc/hosts.allow",
        "/etc/hosts.deny",
        "/etc/inetd.conf",
        "/etc/rc.conf",
        "/etc/rc.local",
        "/etc/crontab",
        "/etc/sysctl.conf",
        "/etc/group",
        "/etc/passwd",
        "/etc/master.passwd",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/ssh/ssh_config",
        "/etc/pf.conf",
        "/etc/resolv.conf",
        "/etc/hosts",
        NULL
    };
    
    for (int i = 0; suspicious_files[i] != NULL; i++) {
        struct stat st;
        if (stat(suspicious_files[i], &st) == 0) {
            /* Check if world-writable */
            if (st.st_mode & S_IWOTH) {
                char msg[256];
                snprintf(msg, sizeof(msg), "World-writable: %o", st.st_mode & 0777);
                add_finding(suspicious_files[i], msg, 2, "Should not be world-writable");
            }
            
            /* Check if group-writable */
            if (st.st_mode & S_IWGRP) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Group-writable: %o", st.st_mode & 0777);
                add_finding(suspicious_files[i], msg, 1, "Should not be group-writable");
            }
        } else {
            add_finding(suspicious_files[i], "Missing file", 1, "File should exist");
        }
    }
}

/* Check for suspicious SUID/SGID binaries */
void check_suid_sgid(void) {
    char cmd[512];
    char line[1024];
    FILE *fp;
    int count = 0;
    int suspicious = 0;
    
    printf("\n" COLOR_BOLD "=== SUID/SGID BINARIES ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    /* Common system SUID binaries that are expected */
    const char *known_suid[] = {
        "/usr/bin/su",
        "/usr/bin/sudo",
        "/usr/bin/passwd",
        "/usr/bin/crontab",
        "/usr/bin/at",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/newgrp",
        "/usr/sbin/ping",
        "/usr/sbin/traceroute",
        "/usr/sbin/ppp",
        "/usr/sbin/setfib",
        NULL
    };
    
    /* Find all SUID/SGID files */
    snprintf(cmd, sizeof(cmd), "find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null");
    fp = popen(cmd, "r");
    if (!fp) {
        printf("  Failed to scan for SUID/SGID files\n");
        return;
    }
    
    printf("  %-50s %-8s\n", "BINARY", "TYPE");
    printf("  %-50s %-8s\n", "------", "----");
    
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        struct stat st;
        if (stat(line, &st) == 0) {
            int is_suid = (st.st_mode & S_ISUID) != 0;
            int is_sgid = (st.st_mode & S_ISGID) != 0;
            
            /* Check if this is a known SUID binary */
            int known = 0;
            for (int i = 0; known_suid[i] != NULL; i++) {
                if (strcmp(line, known_suid[i]) == 0) {
                    known = 1;
                    break;
                }
            }
            
            if (!known) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Unexpected %s binary", 
                         is_suid && is_sgid ? "SUID/SGID" : 
                         is_suid ? "SUID" : "SGID");
                add_finding(line, msg, 2, "Should not be SUID/SGID");
                suspicious++;
            }
            
            count++;
        }
    }
    pclose(fp);
    
    printf("  Total SUID/SGID files: %d\n", count);
    if (suspicious > 0) {
        printf(COLOR_RED "  ⚠ %d suspicious SUID/SGID files found\n" COLOR_RESET, suspicious);
    } else {
        printf(COLOR_GREEN "  ✓ No suspicious SUID/SGID files found\n" COLOR_RESET);
    }
}

/* Check for world-writable system directories */
void check_world_writable_dirs(void) {
    const char *system_dirs[] = {
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/etc",
        "/boot",
        "/lib",
        "/usr/lib",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/local/etc",
        NULL
    };
    
    printf("\n" COLOR_BOLD "=== WORLD-WRITABLE SYSTEM DIRECTORIES ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    int found = 0;
    
    for (int i = 0; system_dirs[i] != NULL; i++) {
        struct stat st;
        if (stat(system_dirs[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            if (st.st_mode & S_IWOTH) {
                printf(COLOR_RED "  ⚠ %s is world-writable (%o)\n" COLOR_RESET, 
                       system_dirs[i], st.st_mode & 0777);
                add_finding(system_dirs[i], "World-writable directory", 2, "Should not be world-writable");
                found++;
            }
        }
    }
    
    if (found == 0) {
        printf(COLOR_GREEN "  ✓ No world-writable system directories found\n" COLOR_RESET);
    }
}

/* Check /etc/rc.conf for suspicious settings */
void check_rc_conf(void) {
    printf("\n" COLOR_BOLD "=== /etc/rc.conf SECURITY CHECK ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    FILE *fp = fopen("/etc/rc.conf", "r");
    if (!fp) {
        printf("  Unable to open /etc/rc.conf\n");
        return;
    }
    
    char line[1024];
    int found = 0;
    
    /* Suspicious settings to look for */
    const char *suspicious_settings[] = {
        "permit_root_login",
        "sshd_enable",
        "telnet_enable",
        "ftp_enable",
        "rlogin_enable",
        "rsh_enable",
        "sendmail_enable",
        "clear_tmp_enable",
        "cron_enable",
        "inetd_enable",
        "ipfw_enable",
        "pf_enable",
        "devfs_system_ruleset",
        NULL
    };
    
    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; suspicious_settings[i] != NULL; i++) {
            if (strstr(line, suspicious_settings[i])) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                printf("  %s\n", line);
                found++;
            }
        }
    }
    
    fclose(fp);
    
    if (found == 0) {
        printf("  No suspicious settings found in rc.conf\n");
    }
}

/* Check for root-owned files in /tmp */
void check_tmp_files(void) {
    printf("\n" COLOR_BOLD "=== /tmp SECURITY CHECK ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    DIR *dir = opendir("/tmp");
    if (!dir) {
        printf("  Failed to open /tmp\n");
        return;
    }
    
    struct dirent *entry;
    int count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        char path[512];
        snprintf(path, sizeof(path), "/tmp/%s", entry->d_name);
        
        struct stat st;
        if (stat(path, &st) == 0) {
            /* Check for suspicious files in /tmp */
            if (st.st_uid == 0 && S_ISREG(st.st_mode)) {
                if (count == 0) {
                    printf("  Root-owned files in /tmp:\n");
                }
                printf("    %s (%ld bytes)\n", entry->d_name, st.st_size);
                count++;
                
                if (strstr(entry->d_name, "..") || 
                    strstr(entry->d_name, " ") ||
                    strstr(entry->d_name, "$") ||
                    strstr(entry->d_name, "`") ||
                    strstr(entry->d_name, ";")) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "Suspicious filename in /tmp: %s", entry->d_name);
                    add_finding(path, msg, 2, "Suspicious filename pattern");
                }
            }
            
            /* Check for world-writable files in /tmp */
            if (st.st_mode & S_IWOTH) {
                add_finding(path, "World-writable file in /tmp", 1, "Should not be world-writable");
            }
        }
    }
    
    closedir(dir);
    
    if (count == 0) {
        printf("  No root-owned files in /tmp\n");
    }
}

/* Check /var/log for suspicious logs */
void check_log_files(void) {
    printf("\n" COLOR_BOLD "=== LOG FILE CHECK ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    const char *log_files[] = {
        "/var/log/messages",
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/maillog",
        "/var/log/cron",
        "/var/log/lastlog",
        "/var/log/wtmp",
        "/var/log/btmp",
        NULL
    };
    
    for (int i = 0; log_files[i] != NULL; i++) {
        struct stat st;
        if (stat(log_files[i], &st) == 0) {
            if (st.st_mode & S_IWOTH) {
                printf(COLOR_YELLOW "  ⚠ %s is world-writable\n" COLOR_RESET, log_files[i]);
                add_finding(log_files[i], "World-writable log file", 1, "Should not be world-writable");
            }
        } else {
            printf("  %s does not exist\n", log_files[i]);
        }
    }
}

/* Check for unauthorized users in /etc/passwd */
void check_passwd(void) {
    printf("\n" COLOR_BOLD "=== USER ACCOUNT CHECK ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) {
        printf("  Unable to open /etc/passwd\n");
        return;
    }
    
    char line[512];
    int count = 0;
    
    printf("  %-16s %-8s %s\n", "USER", "UID", "SHELL");
    printf("  %-16s %-8s %s\n", "----", "---", "-----");
    
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        char *username = strtok(line, ":");
        char *password = strtok(NULL, ":");
        char *uid_str = strtok(NULL, ":");
        char *gid_str = strtok(NULL, ":");
        char *gecos = strtok(NULL, ":");
        char *home = strtok(NULL, ":");
        char *shell = strtok(NULL, ":");
        
        if (username && uid_str) {
            int uid = atoi(uid_str);
            
            /* Check for UID 0 users other than root */
            if (uid == 0 && strcmp(username, "root") != 0) {
                printf(COLOR_RED "  ⚠ %-16s %-8d %s (UID 0!)\n" COLOR_RESET, 
                       username, uid, shell ? shell : "");
                add_finding("/etc/passwd", 
                           "Additional UID 0 user found", 2, 
                           "Only root should have UID 0");
            }
            
            /* Check for users with unusual shells */
            if (shell && (strstr(shell, "/bin/false") || 
                          strstr(shell, "/sbin/nologin") ||
                          strstr(shell, "/dev/null"))) {
                /* This is normal for system accounts */
            }
            
            count++;
        }
    }
    
    fclose(fp);
    printf("  Total users: %d\n", count);
}

/* ============================================================
 * SUSPICIOUS TTY DETECTION
 * ============================================================ */

void detect_suspicious_ttys(void) {
    printf("\n" COLOR_BOLD "=== SUSPICIOUS TTY DETECTION ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    printf("  Looking for TTYs with active processes but no login session...\n\n");
    
    if (!is_proc_mounted()) {
        printf(COLOR_YELLOW "  Warning: /proc not mounted. Run: sudo mount -t procfs proc /proc\n" COLOR_RESET);
        printf("  Detection will be limited.\n");
        return;
    }
    
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        printf("  Failed to open /proc\n");
        return;
    }
    
    struct dirent *pe;
    int found = 0;
    
    while ((pe = readdir(proc_dir)) != NULL) {
        if (!isdigit(pe->d_name[0])) continue;
        
        int pid = atoi(pe->d_name);
        char tty_name[256] = {0};
        char tty_path[512] = {0};
        
        char fd_path[512];
        char link[512];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd/0", pe->d_name);
        
        ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
        if (len > 0) {
            link[len] = '\0';
            if (strncmp(link, "/dev/tty", 8) == 0 ||
                strncmp(link, "/dev/pts/", 9) == 0) {
                strncpy(tty_path, link, sizeof(tty_path) - 1);
                
                const char *tty_name_ptr = strrchr(link, '/');
                if (tty_name_ptr) {
                    strncpy(tty_name, tty_name_ptr + 1, sizeof(tty_name) - 1);
                } else {
                    strncpy(tty_name, link, sizeof(tty_name) - 1);
                }
                
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "who | grep -q '%s'", tty_name);
                int has_login = (system(cmd) == 0);
                
                if (!has_login) {
                    char name[256] = "unknown";
                    char cmdline_path[512];
                    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/comm", pe->d_name);
                    FILE *fp = fopen(cmdline_path, "r");
                    if (fp) {
                        if (fgets(name, sizeof(name), fp)) {
                            char *nl = strchr(name, '\n');
                            if (nl) *nl = '\0';
                        }
                        fclose(fp);
                    }
                    
                    if (!found) {
                        printf("  %-8s %-16s %-20s\n", "PID", "PROCESS", "TTY");
                        printf("  %-8s %-16s %-20s\n", "---", "-------", "---");
                    }
                    printf(COLOR_RED "  %-8d %-16s %-20s" COLOR_RESET "  [SUSPICIOUS]\n",
                           pid, name, tty_path);
                    char msg[256];
                    snprintf(msg, sizeof(msg), "TTY %s active (pid %d) but no login session", 
                             tty_path, pid);
                    add_finding(tty_path, msg, 2, "TTY should have login session");
                    found++;
                }
            }
        }
    }
    
    closedir(proc_dir);
    
    if (!found) {
        printf(COLOR_GREEN "  No suspicious TTYs found.\n" COLOR_RESET);
    } else {
        printf("\n  " COLOR_YELLOW "These TTYs have active processes but no login session." COLOR_RESET "\n");
        printf("  " COLOR_YELLOW "This could indicate a backdoor or unauthorized access." COLOR_RESET "\n");
    }
}

/* ============================================================
 * PRINT ALL FINDINGS
 * ============================================================ */

void print_findings(void) {
    if (num_findings == 0) {
        printf("\n" COLOR_GREEN "✓ No suspicious findings.\n" COLOR_RESET);
        return;
    }
    
    printf("\n" COLOR_BOLD "=== SECURITY FINDINGS SUMMARY ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    int critical = 0, warning = 0, info = 0;
    
    for (int i = 0; i < num_findings; i++) {
        if (findings[i].severity == 2) critical++;
        else if (findings[i].severity == 1) warning++;
        else info++;
    }
    
    printf("  %d critical, %d warning, %d info\n\n", critical, warning, info);
    
    for (int i = 0; i < num_findings; i++) {
        const char *sev = "INFO";
        const char *color = COLOR_BLUE;
        
        if (findings[i].severity == 2) {
            sev = "CRITICAL";
            color = COLOR_RED;
        } else if (findings[i].severity == 1) {
            sev = "WARNING";
            color = COLOR_YELLOW;
        }
        
        printf("%s[%s]%s %s\n", color, sev, COLOR_RESET, findings[i].path);
        printf("    %s\n", findings[i].finding);
        if (findings[i].expected_content[0] != '\0') {
            printf("    Expected: %s\n", findings[i].expected_content);
        }
        printf("\n");
    }
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void) {
    printf(COLOR_CYAN "╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    SYSTEM INFORMATION TOOL                        ║\n");
    printf("║                    FreeBSD System Introspection                   ║\n");
    printf("║                    with Security Checks                          ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    
    /* Check if running as root */
    if (geteuid() != 0) {
        printf(COLOR_YELLOW "\n⚠ Warning: Running without root privileges. Some checks may be limited.\n" COLOR_RESET);
    } else {
        printf(COLOR_GREEN "\n✓ Running as root\n" COLOR_RESET);
    }
    
    /* Check if /proc is mounted */
    if (!is_proc_mounted()) {
        printf(COLOR_YELLOW "\n⚠ Warning: /proc is not mounted.\n" COLOR_RESET);
        printf("  Some features will be limited. Run: sudo mount -t procfs proc /proc\n");
    } else {
        printf(COLOR_GREEN "\n✓ /proc is mounted\n" COLOR_RESET);
    }
    
    /* Print all information */
    print_system_info();
    
    /* Security checks */
    printf("\n" COLOR_BOLD "=== SECURITY CHECKS ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    check_etc_files();
    check_suid_sgid();
    check_world_writable_dirs();
    check_rc_conf();
    check_tmp_files();
    check_log_files();
    check_passwd();
    detect_suspicious_ttys();
    
    /* Print findings summary */
    print_findings();
    
    printf("\n" COLOR_GREEN "Done.\n" COLOR_RESET);
    
    return 0;
}
