/*
 * misc_utils.c - Miscellaneous System Utilities for FreeBSD
 * 
 * This program includes:
 * 1. System uptime check
 * 2. Running processes count
 * 3. Open files count
 * 4. System temperature (if available)
 * 5. User sessions count
 * 6. System load averages
 * 7. Network statistics
 * 8. Disk I/O statistics
 *
 * Compile: cc -Wall -Wextra -O2 misc_utils.c -o misc_utils
 * Run: ./misc_utils [OPTIONS]
 */

#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <dirent.h>

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
 * UTILITY: Get System Uptime
 * ============================================================ */

void print_uptime(void) {
    struct timeval boottime;
    size_t len = sizeof(boottime);
    time_t now = time(NULL);
    
    printf("\n" COLOR_BOLD "=== SYSTEM UPTIME ===\n" COLOR_RESET);
    
    if (sysctlbyname("kern.boottime", &boottime, &len, NULL, 0) == 0) {
        time_t uptime = now - boottime.tv_sec;
        int days = uptime / 86400;
        int hours = (uptime % 86400) / 3600;
        int minutes = (uptime % 3600) / 60;
        
        char boot_str[64];
        struct tm *tm = localtime(&boottime.tv_sec);
        strftime(boot_str, sizeof(boot_str), "%Y-%m-%d %H:%M:%S", tm);
        
        printf("  Boot time: %s\n", boot_str);
        printf("  Uptime:    %d days, %02d:%02d:%02d\n", 
               days, hours, minutes, (int)(uptime % 60));
    } else {
        printf("  Failed to get uptime\n");
    }
}

/* ============================================================
 * UTILITY: Process Count
 * ============================================================ */

void print_process_count(void) {
    struct kinfo_proc *proc_list = NULL;
    size_t len = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int count = 0;
    int zombie = 0;
    int running = 0;
    int sleeping = 0;
    
    printf("\n" COLOR_BOLD "PROCESS STATISTICS\n" COLOR_RESET);
    
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
    
    for (int i = 0; i < count; i++) {
        switch (proc_list[i].ki_stat) {
            case 'R': running++; break;
            case 'S': sleeping++; break;
            case 'Z': zombie++; break;
            default: break;
        }
    }
    
    free(proc_list);
    
    printf("  Total processes: %d\n", count);
    printf("  Running:         %d\n", running);
    printf("  Sleeping:        %d\n", sleeping);
    printf("  Zombie:          %d\n", zombie);
}

/* ============================================================
 * UTILITY: Open Files Count
 * ============================================================ */

void print_open_files(void) {
    int openfiles;
    int maxfiles;
    size_t len;
    
    printf("\n" COLOR_BOLD "=== OPEN FILES ===\n" COLOR_RESET);
    
    len = sizeof(openfiles);
    if (sysctlbyname("kern.openfiles", &openfiles, &len, NULL, 0) == 0) {
        len = sizeof(maxfiles);
        if (sysctlbyname("kern.maxfiles", &maxfiles, &len, NULL, 0) == 0) {
            int percent = (openfiles * 100) / maxfiles;
            printf("  Open files:  %d\n", openfiles);
            printf("  Max files:   %d\n", maxfiles);
            printf("  Usage:       %d%%\n", percent);
            
            if (percent > 80) {
                printf(COLOR_YELLOW "  ⚠ Warning: File descriptor usage is high\n" COLOR_RESET);
            }
        }
    }
}

/* ============================================================
 * UTILITY: System Load
 * ============================================================ */

void print_load_average(void) {
    struct loadavg load;
    size_t len = sizeof(load);
    int mib[2] = {CTL_VM, VM_LOADAVG};
    
    printf("\n" COLOR_BOLD "=== LOAD AVERAGE ===\n" COLOR_RESET);
    
    if (sysctl(mib, 2, &load, &len, NULL, 0) == 0) {
        double load1 = (double)load.ldavg[0] / load.fscale;
        double load5 = (double)load.ldavg[1] / load.fscale;
        double load15 = (double)load.ldavg[2] / load.fscale;
        
        printf("  1 min:  %.2f\n", load1);
        printf("  5 min:  %.2f\n", load5);
        printf("  15 min: %.2f\n", load15);
        
        /* Check CPU count for context */
        int ncpu;
        len = sizeof(ncpu);
        if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0) {
            printf("  CPUs:   %d\n", ncpu);
            if (load1 > ncpu * 0.8) {
                printf(COLOR_YELLOW "  ⚠ Load average is high relative to CPU count\n" COLOR_RESET);
            }
        }
    }
}

/* ============================================================
 * UTILITY: System Temperature
 * ============================================================ */

void print_temperature(void) {
    printf("\n" COLOR_BOLD "=== SYSTEM TEMPERATURE ===\n" COLOR_RESET);
    
    /* Try to read from sysctl */
    int temp;
    size_t len = sizeof(temp);
    
    if (sysctlbyname("hw.acpi.thermal.tz0.temperature", &temp, &len, NULL, 0) == 0) {
        /* Convert from deci-Kelvin to Celsius */
        double celsius = (temp - 2731) / 10.0;
        printf("  CPU temp:    %.1f°C\n", celsius);
        
        if (celsius > 80) {
            printf(COLOR_RED "High temperature detected!\n" COLOR_RESET);
        } else if (celsius > 70) {
            printf(COLOR_YELLOW "Temperature is elevated\n" COLOR_RESET);
        }
    } else if (sysctlbyname("dev.cpu.0.temperature", &temp, &len, NULL, 0) == 0) {
        double celsius = (temp - 2731) / 10.0;
        printf("  CPU temp:    %.1f°C\n", celsius);
    } else {
        /* Try using sysctl with alternative path */
        printf("  Temperature data not available\n");
        printf("  (Try: sysctl hw.acpi.thermal)\n");
    }
}

/* ============================================================
 * UTILITY: User Sessions
 * ============================================================ */

void print_user_sessions(void) {
    printf("\n" COLOR_BOLD "=== USER SESSIONS ===\n" COLOR_RESET);
    
    FILE *fp = popen("who -a 2>/dev/null | wc -l", "r");
    if (fp) {
        char buf[128];
        if (fgets(buf, sizeof(buf), fp)) {
            int users = atoi(buf);
            printf("  Active users: %d\n", users);
            
            /* Show current users */
            printf("\n  Current sessions:\n");
            system("who -a 2>/dev/null | head -10");
        }
        pclose(fp);
    }
}

/* ============================================================
 * UTILITY: Network Statistics
 * ============================================================ */

void print_network_stats(void) {
    printf("\n" COLOR_BOLD "=== NETWORK STATISTICS ===\n" COLOR_RESET);
    
    /* Get interface list */
    FILE *fp = popen("ifconfig -a | grep -E '^[a-z]' | wc -l", "r");
    if (fp) {
        char buf[128];
        if (fgets(buf, sizeof(buf), fp)) {
            int interfaces = atoi(buf);
            printf("  Interfaces:  %d\n", interfaces);
        }
        pclose(fp);
    }
    
    /* Get IP addresses */
    printf("\n  IP Addresses:\n");
    system("ifconfig -a | grep -E 'inet ' | awk '{print \"    \" $2}' 2>/dev/null");
    
    /* Get listening ports */
    fp = popen("sockstat -4 -l 2>/dev/null | grep -v '^USER' | wc -l", "r");
    if (fp) {
        char buf[128];
        if (fgets(buf, sizeof(buf), fp)) {
            int ports = atoi(buf);
            printf("\n  Listening ports: %d\n", ports);
        }
        pclose(fp);
    }
}

/* ============================================================
 * UTILITY: Memory Info
 * ============================================================ */

void print_memory_info(void) {
    printf("\n" COLOR_BOLD "=== MEMORY INFORMATION ===\n" COLOR_RESET);
    
    long physmem;
    size_t len = sizeof(physmem);
    
    if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) == 0) {
        printf("  Physical RAM: %ld MB\n", physmem / (1024 * 1024));
    }
    
    /* Get swap info */
    FILE *fp = popen("swapinfo -m 2>/dev/null | grep -v 'Device' | head -5", "r");
    if (fp) {
        printf("\n  Swap:\n");
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            printf("    %s", line);
        }
        pclose(fp);
    }
}

/* ============================================================
 * UTILITY: Check Pending Reboot
 * ============================================================ */

void print_reboot_status(void) {
    printf("\n" COLOR_BOLD "=== REBOOT STATUS ===\n" COLOR_RESET);
    
    /* Check if /var/run/reboot-required exists (FreeBSD specific) */
    if (access("/var/run/reboot-required", F_OK) == 0) {
        printf(COLOR_YELLOW "System reboot is required\n" COLOR_RESET);
        return;
    }
    
    /* Check if kernel was updated */
    struct stat kernel_st, kernel_old_st;
    if (stat("/boot/kernel/kernel", &kernel_st) == 0 &&
        stat("/boot/kernel/kernel.old", &kernel_old_st) == 0) {
        if (kernel_st.st_mtime > kernel_old_st.st_mtime) {
            printf(COLOR_YELLOW "Kernel has been updated. Reboot recommended.\n" COLOR_RESET);
        } else {
            printf(COLOR_GREEN "No reboot required\n" COLOR_RESET);
        }
    } else {
        printf("  Unable to determine reboot status\n");
    }
}

/* ============================================================
 * UTILITY: Check Hard Drive Health (S.M.A.R.T.)
 * ============================================================ */

void print_disk_health(void) {
    printf("\n" COLOR_BOLD "=== DISK HEALTH (S.M.A.R.T.) ===\n" COLOR_RESET);
    
    /* Check if smartctl is installed */
    if (system("which smartctl > /dev/null 2>&1") != 0) {
        printf("  smartctl not installed. Install sysutils/smartmontools\n");
        return;
    }
    
    /* Get disk list */
    printf("  Available drives:\n");
    system("smartctl --scan 2>/dev/null | awk '{print \"    \" $1}'");
    
    printf("\n  To check a specific drive:\n");
    printf("  smartctl -a /dev/ada0\n");
    printf("  smartctl -a /dev/da0\n");
}

/* ============================================================
 * UTILITY: Check Failed Logins
 * ============================================================ */

void print_failed_logins(void) {
    printf("\n" COLOR_BOLD "=== FAILED LOGINS ===\n" COLOR_RESET);
    
    /* Check /var/log/auth.log for failed logins */
    FILE *fp = popen("grep -i 'authentication failure\\|failed login' /var/log/auth.log 2>/dev/null | tail -10", "r");
    if (fp) {
        char line[512];
        int count = 0;
        
        printf("  Recent failed logins:\n");
        while (fgets(line, sizeof(line), fp)) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            printf("    %s\n", line);
            count++;
        }
        
        if (count == 0) {
            printf("    No recent failed logins\n");
        }
        pclose(fp);
    } else {
        printf("  /var/log/auth.log not found\n");
    }
}

/* ============================================================
 * UTILITY: Check System Security Level
 * ============================================================ */

void print_securelevel(void) {
    printf("\n" COLOR_BOLD "=== SECURELEVEL ===\n" COLOR_RESET);
    
    int securelevel;
    size_t len = sizeof(securelevel);
    
    if (sysctlbyname("kern.securelevel", &securelevel, &len, NULL, 0) == 0) {
        printf("  Current securelevel: %d\n", securelevel);
        printf("  Description:         ");
        
        switch (securelevel) {
            case -1: printf("Permanently insecure (debug mode)\n"); break;
            case 0:  printf("Unsecured (normal mode)\n"); break;
            case 1:  printf("Secure mode (system files protected)\n"); break;
            case 2:  printf("Highly secure (disk writes restricted)\n"); break;
            case 3:  printf("Most secure (kernel access restricted)\n"); break;
            default: printf("Unknown\n"); break;
        }
        
        if (securelevel == 0) {
            printf(COLOR_YELLOW "  ⚠ System is in unsecured mode\n" COLOR_RESET);
            printf("  To increase security, add to /etc/sysctl.conf:\n");
            printf("  kern.securelevel=1\n");
        }
    }
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(int argc, char **argv) {
    int all = 0;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            all = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("  -a, --all    Show all information\n");
            printf("  -h, --help   Show this help\n");
            printf("\nAvailable checks:\n");
            printf("  uptime, processes, files, load, temperature,\n");
            printf("  users, network, memory, reboot, disk, logins, securelevel\n");
            return 0;
        }
    }
    
    printf("                    MISCELLANEOUS UTILITIES                        \n");
    printf("                    FreeBSD System Tools                           \n");
    
    printf(COLOR_BLUE "\nRunning checks...\n" COLOR_RESET);
    
    if (all) {
        print_uptime();
        print_process_count();
        print_open_files();
        print_load_average();
        print_temperature();
        print_user_sessions();
        print_network_stats();
        print_memory_info();
        print_reboot_status();
        print_disk_health();
        print_failed_logins();
        print_securelevel();
    } else {
        /* Default: show essential info */
        print_uptime();
        print_load_average();
        print_process_count();
        print_open_files();
        print_memory_info();
        print_user_sessions();
        print_reboot_status();
        
        printf("\n" COLOR_BLUE "To see all information, run: %s -a\n" COLOR_RESET, argv[0]);
    }
    
    printf("\n" COLOR_GREEN "Done.\n" COLOR_RESET);
    
    return 0;
}
