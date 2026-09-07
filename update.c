/*
 * update_system.c - FreeBSD System Update Utility
 * 
 * This program checks for and applies system updates:
 * 1. freebsd-update for base system
 * 2. pkg for userland packages
 * 3. Ports tree updates
 *
 * Compile: cc -Wall -Wextra -O2 update_system.c -o update_system
 * Run: sudo ./update_system
 */

#define __BSD_VISIBLE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

/* ============================================================
 * COLORS
 * ============================================================ */

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

/* ============================================================
 * FUNCTIONS
 * ============================================================ */

int is_root(void) {
    return geteuid() == 0;
}

void print_header(const char *title) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("  %s\n", title);
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
}

void run_command(const char *cmd, const char *desc) {
    printf("\n" COLOR_BLUE "→ %s...\n" COLOR_RESET, desc);
    printf("%s\n", cmd);
    printf("────────────────────────────────────────────\n");
    int status = system(cmd);
    if (status == 0) {
        printf(COLOR_GREEN "✓ %s completed successfully\n" COLOR_RESET, desc);
    } else {
        printf(COLOR_RED "✗ %s failed (exit code: %d)\n" COLOR_RESET, desc, status);
    }
}

int check_updates_available(void) {
    printf("\n" COLOR_BLUE "Checking for updates...\n" COLOR_RESET);
    
    /* Check freebsd-update */
    printf("\n  " COLOR_YELLOW "Checking base system updates...\n" COLOR_RESET);
    int status = system("freebsd-update fetch -q 2>&1");
    
    if (status == 0) {
        printf(COLOR_GREEN "  ✓ Base system is up to date\n" COLOR_RESET);
    } else {
        printf(COLOR_YELLOW "  ⚠ Base system updates available\n" COLOR_RESET);
    }
    
    /* Check pkg updates */
    printf("\n  " COLOR_YELLOW "Checking package updates...\n" COLOR_RESET);
    status = system("pkg update -q 2>&1 && pkg audit -q 2>&1 | wc -l");
    
    return status;
}

void update_base_system(void) {
    print_header("UPDATING BASE SYSTEM");
    
    run_command("freebsd-update fetch", "Fetching base updates");
    run_command("freebsd-update install", "Installing base updates");
}

void update_packages(void) {
    print_header("UPDATING PACKAGES");
    
    run_command("pkg update -f", "Updating package repository");
    run_command("pkg upgrade -y", "Upgrading packages");
    run_command("pkg autoremove -y", "Removing unused packages");
    run_command("pkg clean -y", "Cleaning package cache");
}

void update_ports(void) {
    print_header("UPDATING PORTS TREE");
    
    if (system("test -d /usr/ports && echo 'exists' 2>/dev/null") == 0) {
        run_command("portsnap fetch update", "Updating ports tree");
    } else {
        printf(COLOR_YELLOW "  ⚠ Ports tree not found. Install with: portsnap fetch extract\n" COLOR_RESET);
    }
}

void check_reboot_required(void) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    REBOOT CHECK\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    
    /* Check if kernel was updated */
    struct stat kernel_st, boot_st;
    if (stat("/boot/kernel/kernel", &kernel_st) == 0 &&
        stat("/boot/kernel/kernel.old", &boot_st) == 0) {
        if (kernel_st.st_mtime > boot_st.st_mtime) {
            printf(COLOR_YELLOW "  ⚠ Kernel has been updated. System reboot is recommended.\n" COLOR_RESET);
        } else {
            printf(COLOR_GREEN "  ✓ No reboot needed for kernel updates\n" COLOR_RESET);
        }
    }
    
    /* Check if any packages need reboot */
    int status = system("pkg info -r kernel 2>/dev/null | grep -q .");
    if (status == 0) {
        printf(COLOR_YELLOW "  ⚠ Some packages may require a reboot.\n" COLOR_RESET);
    }
}

void print_summary(int updates_applied) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════════════════\n");
    printf("                    UPDATE SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    
    if (updates_applied) {
        printf(COLOR_GREEN "  ✓ Updates were applied successfully\n" COLOR_RESET);
    } else {
        printf(COLOR_YELLOW "  ⚠ No updates were applied\n" COLOR_RESET);
    }
    
    printf("\n  %sNext Steps:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  • Check the system logs: tail -100 /var/log/messages\n");
    printf("  • Verify services are running: service -l\n");
    printf("  • Reboot if recommended: sudo shutdown -r now\n");
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(int argc, char **argv) {
    int updates_applied = 0;
    int check_only = 0;
    int no_pkg = 0;
    int no_base = 0;
    int no_ports = 0;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0) {
            check_only = 1;
        } else if (strcmp(argv[i], "--no-pkg") == 0) {
            no_pkg = 1;
        } else if (strcmp(argv[i], "--no-base") == 0) {
            no_base = 1;
        } else if (strcmp(argv[i], "--no-ports") == 0) {
            no_ports = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("  -c, --check     Only check for updates, don't apply\n");
            printf("  --no-pkg        Skip package updates\n");
            printf("  --no-base       Skip base system updates\n");
            printf("  --no-ports      Skip ports tree updates\n");
            printf("  -h, --help      Show this help\n");
            return 0;
        }
    }
    
    printf(COLOR_CYAN "╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    SYSTEM UPDATE UTILITY                          ║\n");
    printf("║                    FreeBSD System Maintenance                     ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    
    if (!is_root()) {
        printf(COLOR_RED "\n  ✗ This tool must be run as root.\n" COLOR_RESET);
        printf("  Run: sudo %s\n", argv[0]);
        return 1;
    }
    
    printf(COLOR_GREEN "\n✓ Running as root\n" COLOR_RESET);
    
    if (check_only) {
        printf("\n" COLOR_BLUE "Check mode: Only checking for updates\n" COLOR_RESET);
        check_updates_available();
        return 0;
    }
    
    /* Show system info */
    printf("\n" COLOR_BOLD "System Information:\n" COLOR_RESET);
    system("uname -a");
    
    /* Update base system */
    if (!no_base) {
        update_base_system();
        updates_applied = 1;
    } else {
        printf(COLOR_YELLOW "\n  ⚠ Skipping base system updates\n" COLOR_RESET);
    }
    
    /* Update packages */
    if (!no_pkg) {
        update_packages();
        updates_applied = 1;
    } else {
        printf(COLOR_YELLOW "\n  ⚠ Skipping package updates\n" COLOR_RESET);
    }
    
    /* Update ports */
    if (!no_ports) {
        update_ports();
        updates_applied = 1;
    } else {
        printf(COLOR_YELLOW "\n  ⚠ Skipping ports tree updates\n" COLOR_RESET);
    }
    
    /* Check if reboot is needed */
    check_reboot_required();
    
    /* Summary */
    print_summary(updates_applied);
    
    return 0;
}
