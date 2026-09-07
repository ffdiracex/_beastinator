/*
 * sysinfo.c - Simple System Information Tool for FreeBSD
 * 
 * This program demonstrates:
 * 1. Reading /proc for process information
 * 2. Reading /dev for device information
 * 3. Using sysctl for kernel information
 * 4. Detecting TTYs and their usage
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

/* ============================================================
 * SYSTEM INFORMATION
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
    
    /* Hostname */
    len = sizeof(buf);
    if (sysctlbyname("kern.hostname", buf, &len, NULL, 0) == 0) {
        printf("  Hostname:   %s\n", buf);
    }
    
    /* OS Release */
    len = sizeof(buf);
    if (sysctlbyname("kern.osrelease", buf, &len, NULL, 0) == 0) {
        printf("  OS Release: %s\n", buf);
    }
    
    /* Kernel Version */
    len = sizeof(buf);
    if (sysctlbyname("kern.version", buf, &len, NULL, 0) == 0) {
        printf("  Kernel:     %s\n", buf);
    }
    
    /* CPU Model */
    len = sizeof(model);
    if (sysctlbyname("hw.model", model, &len, NULL, 0) == 0) {
        printf("  CPU:        %s\n", model);
    }
    
    /* CPU Cores */
    len = sizeof(ncpu);
    if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0) {
        printf("  Cores:      %d\n", ncpu);
    }
    
    /* Memory */
    len = sizeof(physmem);
    if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) == 0) {
        printf("  Memory:     %ld MB\n", physmem / (1024 * 1024));
    }
    
    /* Boot Time */
    len = sizeof(boot_time);
    if (sysctlbyname("kern.boottime", &boot_time, &len, NULL, 0) == 0) {
        char timebuf[64];
        format_time(boot_time, timebuf, sizeof(timebuf));
        printf("  Boot Time:  %s\n", timebuf);
    }
    
    /* User */
    printf("  User:       %s\n", get_username());
    
    /* Uptime */
    FILE *fp = popen("uptime", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            /* Remove newline */
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            printf("  Uptime:     %s\n", line);
        }
        pclose(fp);
    }
}

/* ============================================================
 * PROCESS INFORMATION
 * ============================================================ */

void print_processes(void) {
    struct kinfo_proc *proc_list = NULL;
    size_t len = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int count = 0;
    
    printf("\n" COLOR_BOLD "=== PROCESSES (first 20) ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    /* Get process list via sysctl */
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        printf("  Failed to get process list\n");
        return;
    }
    
    proc_list = malloc(len);
    if (!proc_list) {
        printf("  Memory allocation failed\n");
        return;
    }
    
    if (sysctl(mib, 4, proc_list, &len, NULL, 0) < 0) {
        printf("  Failed to read process list\n");
        free(proc_list);
        return;
    }
    
    count = len / sizeof(struct kinfo_proc);
    
    printf("  %-8s %-16s %-8s %-8s\n", "PID", "NAME", "UID", "STATE");
    printf("  %-8s %-16s %-8s %-8s\n", "---", "----", "---", "-----");
    
    int limit = count < 20 ? count : 20;
    for (int i = 0; i < limit; i++) {
        struct kinfo_proc *kp = &proc_list[i];
        const char *state = "unknown";
        
        switch (kp->ki_stat) {
            case 'S': state = "sleeping"; break;
            case 'R': state = "running"; break;
            case 'D': state = "disk_sleep"; break;
            case 'Z': state = "zombie"; break;
            case 'T': state = "stopped"; break;
            case 'I': state = "idle"; break;
            case 'W': state = "waiting"; break;
            default: state = "unknown"; break;
        }
        
        printf("  %-8d %-16s %-8d %-8s\n",
               kp->ki_pid, kp->ki_comm, kp->ki_uid, state);
    }
    
    if (count > 20) {
        printf("  ... and %d more\n", count - 20);
    }
    
    free(proc_list);
}

/* ============================================================
 * TTY INFORMATION
 * ============================================================ */

void print_ttys(void) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    int count = 0;
    
    printf("\n" COLOR_BOLD "=== TTY DEVICES ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    dir = opendir("/dev");
    if (!dir) {
        printf("  Failed to open /dev\n");
        return;
    }
    
    printf("  %-20s %-8s %-8s\n", "NAME", "TYPE", "ACTIVE");
    printf("  %-20s %-8s %-8s\n", "----", "----", "------");
    
    while ((entry = readdir(dir)) != NULL) {
        char path[512];
        snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
        
        if (stat(path, &st) < 0) continue;
        
        /* Skip non-character devices */
        if (!S_ISCHR(st.st_mode)) continue;
        
        /* Look for TTY devices */
        const char *name = entry->d_name;
        int is_tty = 0;
        
        if (strncmp(name, "tty", 3) == 0 && strlen(name) > 3) {
            if (isdigit(name[3]) || name[3] == 'v' || name[3] == 'u') {
                is_tty = 1;
            }
        } else if (strncmp(name, "pts/", 4) == 0) {
            is_tty = 1;
        } else if (strcmp(name, "console") == 0) {
            is_tty = 1;
        }
        
        if (!is_tty) continue;
        
        /* Check if TTY is active */
        int active = 0;
        int pid = -1;
        
        /* Try to find if any process uses this TTY */
        if (is_proc_mounted()) {
            DIR *proc_dir = opendir("/proc");
            if (proc_dir) {
                struct dirent *pe;
                while ((pe = readdir(proc_dir)) != NULL) {
                    if (!isdigit(pe->d_name[0])) continue;
                    
                    char fd_path[512];
                    snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd/0", pe->d_name);
                    char link[512];
                    ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
                    if (len > 0) {
                        link[len] = '\0';
                        if (strcmp(link, path) == 0) {
                            active = 1;
                            pid = atoi(pe->d_name);
                            break;
                        }
                    }
                }
                closedir(proc_dir);
            }
        }
        
        printf("  %-20s %-8s %s\n", 
               name,
               S_ISCHR(st.st_mode) ? "char" : "other",
               active ? "yes (pid " : "no");
        
        if (active && pid > 0) {
            printf("%d)\n", pid);
        } else if (active) {
            printf("yes\n");
        } else {
            printf("no\n");
        }
        
        count++;
    }
    
    closedir(dir);
    printf("  Total TTY devices: %d\n", count);
}

/* ============================================================
 * DEVICE INFORMATION
 * ============================================================ */

void print_devices(void) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    int char_count = 0;
    int block_count = 0;
    int total_count = 0;
    
    printf("\n" COLOR_BOLD "=== DEVICE SUMMARY ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    dir = opendir("/dev");
    if (!dir) {
        printf("  Failed to open /dev\n");
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        char path[512];
        snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
        
        if (stat(path, &st) < 0) continue;
        
        total_count++;
        
        if (S_ISCHR(st.st_mode)) {
            char_count++;
        } else if (S_ISBLK(st.st_mode)) {
            block_count++;
        }
    }
    
    closedir(dir);
    
    printf("  Total devices: %d\n", total_count);
    printf("  Character devices: %d\n", char_count);
    printf("  Block devices: %d\n", block_count);
}

/* ============================================================
 * MODULE INFORMATION
 * ============================================================ */

void print_modules(void) {
    int mib[2] = {CTL_KERN, KERN_MODULE};
    size_t len = 0;
    struct module_stat *mods = NULL;
    int count = 0;
    
    printf("\n" COLOR_BOLD "=== LOADED KERNEL MODULES ===" COLOR_RESET "\n");
    printf("────────────────────────────────────────────\n");
    
    if (sysctl(mib, 2, NULL, &len, NULL, 0) < 0) {
        printf("  Failed to get module list\n");
        return;
    }
    
    if (len == 0) {
        printf("  No modules loaded\n");
        return;
    }
    
    mods = malloc(len);
    if (!mods) {
        printf("  Memory allocation failed\n");
        return;
    }
    
    if (sysctl(mib, 2, mods, &len, NULL, 0) < 0) {
        printf("  Failed to read module list\n");
        free(mods);
        return;
    }
    
    count = len / sizeof(struct module_stat);
    
    printf("  %-6s %-20s %-10s\n", "ID", "MODULE", "SIZE");
    printf("  %-6s %-20s %-10s\n", "--", "------", "----");
    
    for (int i = 0; i < count && i < 20; i++) {
        struct module_stat *ms = &mods[i];
        printf("  %-6d %-20s %-10zu\n",
               ms->ms_id, ms->ms_name, ms->ms_size);
    }
    
    if (count > 20) {
        printf("  ... and %d more\n", count - 20);
    }
    
    free(mods);
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
    
    /* First, get list of active TTYs from /dev/tty* */
    struct dirent *pe;
    int found = 0;
    
    while ((pe = readdir(proc_dir)) != NULL) {
        if (!isdigit(pe->d_name[0])) continue;
        
        int pid = atoi(pe->d_name);
        char tty_name[256] = {0};
        char tty_path[512] = {0};
        
        /* Check if process has a TTY via fd/0 */
        char fd_path[512];
        char link[512];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd/0", pe->d_name);
        
        ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
        if (len > 0) {
            link[len] = '\0';
            if (strncmp(link, "/dev/tty", 8) == 0 ||
                strncmp(link, "/dev/pts/", 9) == 0) {
                strncpy(tty_path, link, sizeof(tty_path) - 1);
                
                /* Extract TTY name */
                const char *tty_name_ptr = strrchr(link, '/');
                if (tty_name_ptr) {
                    strncpy(tty_name, tty_name_ptr + 1, sizeof(tty_name) - 1);
                } else {
                    strncpy(tty_name, link, sizeof(tty_name) - 1);
                }
                
                /* Check if this TTY appears in 'who' output */
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "who | grep -q '%s'", tty_name);
                int has_login = (system(cmd) == 0);
                
                if (!has_login) {
                    /* Get process name */
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
 * MAIN
 * ============================================================ */

int main(void) {
    printf(COLOR_CYAN "╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    SYSTEM INFORMATION TOOL                        ║\n");
    printf("║                    FreeBSD System Introspection                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    
    /* Check if /proc is mounted */
    if (!is_proc_mounted()) {
        printf(COLOR_YELLOW "\n⚠ Warning: /proc is not mounted.\n" COLOR_RESET);
        printf("  Some features will be limited. Run: sudo mount -t procfs proc /proc\n");
    } else {
        printf(COLOR_GREEN "\n✓ /proc is mounted\n" COLOR_RESET);
    }
    
    /* Print all information */
    print_system_info();
    print_processes();
    print_ttys();
    print_devices();
    print_modules();
    detect_suspicious_ttys();
    
    printf("\n" COLOR_GREEN "Done.\n" COLOR_RESET);
    
    return 0;
}
