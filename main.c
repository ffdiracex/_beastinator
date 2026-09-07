/*
 * main.c - Unified SYSSEC Entry Point
 * 
 * This is the main program that ties together all SYSSEC / beastinator components:
 * - Configuration loading
 * - Logging
 * - System scanning
 * - Report generation
 * - Alerting
 * - Scheduling
 *
 * Compile: cc -Wall -Wextra -O2 main.c config.c logging.c report.c alert.c scheduler.c utils.c scanner.c -o syssec -lm -pthread
 * Run: ./syssec [OPTIONS]
 */

#define __BSD_VISIBLE 1

#include "syssec.h"
#include "config.h"
#include "logging.h"
#include "report.h"
#include "alert.h"
#include "scheduler.h"
#include "utils.h"
#include "scanner.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

static syssec_config_t config;
static syssec_report_t report;
static int verbose = 0;
static int quiet = 0;
static const char *config_path = NULL;
static const char *output_format = "text";
static const char *output_file = NULL;

/* ============================================================
 * FUNCTION PROTOTYPES
 * ============================================================ */

static void print_usage(const char *progname);
static int parse_arguments(int argc, char **argv);
static void setup_signal_handlers(void);
static void signal_handler(int sig);
static int run_scan(void);
static int run_scheduler(void);
static int run_alert_test(void);
static int run_config_tool(void);

/* ============================================================
 * USAGE
 * ============================================================ */

static void print_usage(const char *progname) {
    printf("SYSSEC - System Security Tools for FreeBSD\n");
    printf("Version: %s\n", SYSSEC_VERSION);
    printf("\n");
    printf("Usage: %s [OPTIONS] [COMMAND]\n", progname);
    printf("\n");
    printf("Commands:\n");
    printf("  scan              Run system security scan (default)\n");
    printf("  report            Generate report from last scan\n");
    printf("  schedule          Manage scheduled scans\n");
    printf("  alert-test        Test alert system\n");
    printf("  config            Manage configuration\n");
    printf("  help              Show this help\n");
    printf("\n");
    printf("Options:\n");
    printf("  -c, --config FILE     Use configuration file\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -q, --quiet           Quiet mode (no output)\n");
    printf("  -o, --output FILE     Output file for report\n");
    printf("  -f, --format FORMAT   Output format: text, json, html\n");
    printf("  -h, --help            Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s scan                # Run a scan\n", progname);
    printf("  %s -v scan             # Run with verbose output\n", progname);
    printf("  %s -o report.html -f html scan  # Generate HTML report\n", progname);
    printf("  %s schedule install    # Install scheduled scans\n", progname);
    printf("  %s alert-test          # Test alert system\n", progname);
    printf("\n");
    printf("Configuration:\n");
    printf("  Default config: ~/.syssec.conf\n");
    printf("  System config: /etc/syssec/syssec.conf\n");
    printf("\n");
}

/* ============================================================
 * SIGNAL HANDLING
 * ============================================================ */

static volatile int signal_received = 0;

static void signal_handler(int sig) {
    signal_received = sig;
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\n" COLOR_YELLOW "Received signal %d, shutting down...\n" COLOR_RESET, sig);
        log_info("Received signal %d, shutting down", sig);
    }
}

static void setup_signal_handlers(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
}

/* ============================================================
 * COMMAND: SCAN
 * ============================================================ */

static int run_scan(void) {
    int result;
    scanner_state_t *scanner;
    
    log_info("Starting system scan");
    
    if (!quiet) {
        printf("\n" COLOR_BOLD "═══ SYSSEC System Scan ═══\n" COLOR_RESET);
        printf("  Config: %s\n", config_path ? config_path : "(default)");
        printf("  Verbose: %s\n", verbose ? "yes" : "no");
        printf("  Format: %s\n", output_format);
        printf("\n");
    }
    
    /* Initialize scanner */
    if (scanner_init(&config) != SYSSEC_OK) {
        log_error("Failed to initialize scanner");
        return 1;
    }
    
    /* Run scan */
    result = scanner_run();
    if (result != SYSSEC_OK) {
        log_error("Scan failed with error: %d", result);
        return 1;
    }
    
    /* Export to report */
    scanner_export_to_report(&report);
    
    /* Print summary */
    if (!quiet) {
        scanner_print_summary();
    }
    
    /* Print detailed results if verbose */
    if (verbose && !quiet) {
        scanner_print_results();
    }
    
    /* Save report if configured */
    if (config.save_reports) {
        const char *format = output_format;
        if (strcmp(format, "text") == 0) {
            format = "html"; /* Default to HTML for saved reports */
        }
        
        char report_name[256];
        snprintf(report_name, sizeof(report_name), "syssec_scan_%ld", time(NULL));
        report_save(&report, config.report_dir, report_name, format);
        report_cleanup_old(config.report_dir, config.report_retention_days);
        
        if (!quiet) {
            printf("\n" COLOR_GREEN "Report saved to: %s/%s.%s\n" COLOR_RESET,
                   config.report_dir, report_name, format);
        }
    }
    
    /* Output to file if requested */
    if (output_file) {
        char *data = NULL;
        if (strcmp(output_format, "json") == 0) {
            data = report_generate_json(&report);
        } else if (strcmp(output_format, "html") == 0) {
            data = report_generate_html(&report);
        } else {
            data = report_generate_text(&report);
        }
        
        if (data) {
            util_write_file(output_file, data, 0);
            if (!quiet) {
                printf(COLOR_GREEN "Output written to: %s\n" COLOR_RESET, output_file);
            }
            free(data);
        }
    }
    
    /* Send alerts for critical issues */
    if (config.enable_alerts) {
        int critical_found = 0;
        char alert_msg[4096] = {0};
        
        for (int i = 0; i < scanner_get_results(); i++) {
            /* We need to get results from scanner - this is simplified */
            /* In production, we'd expose a scanner_get_result() function */
        }
        
        /* This is a placeholder - the actual alert logic would be more complex */
        if (critical_found > 0) {
            char full_msg[4096];
            char hostname[MAX_NAME];
            util_get_hostname(hostname, sizeof(hostname));
            
            snprintf(full_msg, sizeof(full_msg),
                    "SYSSEC Scan Alert\n"
                    "Host: %s\n"
                    "Time: %s\n"
                    "Critical Issues Found: %d\n"
                    "\n%s",
                    hostname,
                    ctime(&(time_t){time(NULL)}),
                    critical_found,
                    alert_msg);
            
            if (alert_should_alert("syssec_scan", "critical", 
                                   config.alert_cooldown_hours)) {
                alert_send(config.alert_email, config.alert_command,
                          "SYSSEC: Critical Issues Found", full_msg);
            }
        }
    }
    
    /* Cleanup */
    scanner_cleanup();
    report_free(&report);
    
    log_info("Scan completed successfully");
    return 0;
}

/* ============================================================
 * COMMAND: SCHEDULER
 * ============================================================ */

static int run_scheduler(void) {
    const char *subcmd = NULL;
    
    /* Check for subcommand (the parser will handle this) */
    /* For now, just show status */
    printf("\n" COLOR_BOLD "═══ SYSSEC Scheduler ═══\n" COLOR_RESET);
    printf("\n");
    
    scheduler_list();
    
    if (config.schedule_enabled) {
        printf("\n" COLOR_GREEN "Scheduled scans are enabled\n" COLOR_RESET);
        printf("  Schedule: %s\n", config.schedule_cron);
        printf("  Run: sudo %s schedule install\n", "syssec");
    } else {
        printf("\n" COLOR_YELLOW "Scheduled scans are disabled\n" COLOR_RESET);
        printf("  Enable in config: schedule_enabled = yes\n");
        printf("  Or run: sudo %s schedule install\n", "syssec");
    }
    
    return 0;
}

/* ============================================================
 * COMMAND: SCHEDULER INSTALL
 * ============================================================ */

static int run_scheduler_install(void) {
    char command[1024];
    
    printf("\n" COLOR_BOLD "═══ Installing SYSSEC Scheduled Scan ═══\n" COLOR_RESET);
    
    /* Build command */
    snprintf(command, sizeof(command), "%s scan --config %s", 
             "syssec", config_path ? config_path : "~/.syssec.conf");
    
    /* Install cron job */
    if (scheduler_install(config.schedule_cron, command) == SYSSEC_OK) {
        printf(COLOR_GREEN "✓ Scheduled scan installed\n" COLOR_RESET);
        printf("  Schedule: %s\n", config.schedule_cron);
        printf("  Command: %s\n", command);
        printf("\n");
        printf("  To remove: %s schedule remove\n", "syssec");
    } else {
        printf(COLOR_RED "✗ Failed to install scheduled scan\n" COLOR_RESET);
        printf("  Make sure crontab is accessible\n");
        return 1;
    }
    
    return 0;
}

/* ============================================================
 * COMMAND: SCHEDULER REMOVE
 * ============================================================ */

static int run_scheduler_remove(void) {
    char command[1024];
    
    printf("\n" COLOR_BOLD "═══ Removing SYSSEC Scheduled Scan ═══\n" COLOR_RESET);
    
    snprintf(command, sizeof(command), "%s scan", "syssec");
    
    if (scheduler_remove(command) == SYSSEC_OK) {
        printf(COLOR_GREEN "✓ Scheduled scan removed\n" COLOR_RESET);
    } else {
        printf(COLOR_YELLOW "No scheduled scan found\n" COLOR_RESET);
    }
    
    return 0;
}

/* ============================================================
 * COMMAND: ALERT TEST
 * ============================================================ */

static int run_alert_test(void) {
    char hostname[MAX_NAME];
    
    printf("\n" COLOR_BOLD "═══ SYSSEC Alert Test ═══\n" COLOR_RESET);
    printf("\n");
    
    util_get_hostname(hostname, sizeof(hostname));
    
    char message[1024];
    snprintf(message, sizeof(message),
            "This is a test alert from SYSSEC\n"
            "Host: %s\n"
            "Time: %s\n"
            "If you received this, alerts are working.",
            hostname,
            ctime(&(time_t){time(NULL)}));
    
    printf("  Email: %s\n", config.alert_email);
    printf("  Command: %s\n", config.alert_command);
    printf("\n");
    printf("  Sending test alert...\n");
    
    if (alert_send(config.alert_email, config.alert_command,
                   "SYSSEC Test Alert", message) == SYSSEC_OK) {
        printf(COLOR_GREEN "✓ Test alert sent\n" COLOR_RESET);
    } else {
        printf(COLOR_YELLOW "⚠ Test alert may have failed\n" COLOR_RESET);
        printf("  Check email configuration or command\n");
    }
    
    return 0;
}

/* ============================================================
 * COMMAND: CONFIG
 * ============================================================ */

static int run_config_tool(void) {
    printf("\n" COLOR_BOLD "═══ SYSSEC Configuration ═══\n" COLOR_RESET);
    printf("\n");
    
    if (config_path) {
        printf("  Config file: %s\n", config_path);
    } else {
        char default_path[MAX_PATH];
        syssec_config_default_path(default_path, sizeof(default_path));
        printf("  Config file: %s (default)\n", default_path);
    }
    
    syssec_config_print(&config);
    
    return 0;
}

/* ============================================================
 * COMMAND: REPORT
 * ============================================================ */

static int run_report_command(void) {
    printf("\n" COLOR_BOLD "═══ SYSSEC Report Generation ═══\n" COLOR_RESET);
    printf("\n");
    
    /* For now, just run a scan and generate report */
    /* In production, this would load the last saved report */
    
    printf("  Running scan to generate report...\n");
    return run_scan();
}

/* ============================================================
 * ARGUMENT PARSING
 * ============================================================ */

static int parse_arguments(int argc, char **argv) {
    int i;
    int has_command = 0;
    const char *command = NULL;
    
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            /* Option */
            if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
                if (i + 1 < argc) {
                    config_path = argv[++i];
                } else {
                    fprintf(stderr, "Error: --config requires an argument\n");
                    return 1;
                }
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
                verbose = 1;
            } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
                quiet = 1;
                verbose = 0;
            } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
                if (i + 1 < argc) {
                    output_file = argv[++i];
                } else {
                    fprintf(stderr, "Error: --output requires an argument\n");
                    return 1;
                }
            } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0) {
                if (i + 1 < argc) {
                    output_format = argv[++i];
                } else {
                    fprintf(stderr, "Error: --format requires an argument\n");
                    return 1;
                }
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                print_usage(argv[0]);
                exit(0);
            } else {
                fprintf(stderr, "Unknown option: %s\n", argv[i]);
                return 1;
            }
        } else {
            /* Command */
            if (has_command) {
                fprintf(stderr, "Warning: Multiple commands specified, using: %s\n", command);
            } else {
                command = argv[i];
                has_command = 1;
            }
        }
    }
    
    /* Default command */
    if (!has_command) {
        command = "scan";
    }
    
    /* Save command for later use */
    if (strcmp(command, "scan") == 0) {
        return 0;
    } else if (strcmp(command, "report") == 0) {
        return 0;
    } else if (strcmp(command, "schedule") == 0) {
        /* Check for schedule subcommand */
        int has_subcmd = 0;
        for (int j = 1; j < argc; j++) {
            if (strcmp(argv[j], "install") == 0) {
                return 0;
            } else if (strcmp(argv[j], "remove") == 0) {
                return 0;
            }
        }
        return 0;
    } else if (strcmp(command, "alert-test") == 0) {
        return 0;
    } else if (strcmp(command, "config") == 0) {
        return 0;
    } else if (strcmp(command, "help") == 0) {
        print_usage(argv[0]);
        exit(0);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}

/* ============================================================
 * DETERMINE COMMAND
 * ============================================================ */

static const char* get_command(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            return argv[i];
        }
    }
    return "scan";
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(int argc, char **argv) {
    int result = 0;
    const char *command;
    char default_config[MAX_PATH];
    char log_path[MAX_PATH];
    
    /* Print banner unless quiet */
    if (!quiet) {
        syssec_banner();
    }
    
    /* Parse arguments */
    if (parse_arguments(argc, argv) != 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Load configuration */
    if (!config_path) {
        syssec_config_default_path(default_config, sizeof(default_config));
        config_path = default_config;
    }
    
    if (syssec_config_load(&config, config_path) != SYSSEC_OK) {
        fprintf(stderr, "Warning: Could not load config from %s, using defaults\n", config_path);
        syssec_config_init(&config);
    }
    
    /* Override config with command-line options */
    if (verbose) config.verbose = 1;
    if (quiet) config.use_colors = 0;
    
    /* Initialize logging */
    snprintf(log_path, sizeof(log_path), "%s/%s", config.log_dir, config.log_file);
    log_init(config.log_dir, config.log_file, 
             config.log_level > 2 ? LOG_LEVEL_INFO : LOG_LEVEL_DEBUG);
    
    /* Setup signal handlers */
    setup_signal_handlers();
    
    /* Log startup */
    log_info("SYSSEC v%s starting", SYSSEC_VERSION);
    log_info("Command: %s", get_command(argc, argv));
    
    /* Execute command */
    command = get_command(argc, argv);
    
    if (strcmp(command, "scan") == 0) {
        result = run_scan();
    } else if (strcmp(command, "report") == 0) {
        result = run_report_command();
    } else if (strcmp(command, "schedule") == 0) {
        /* Check for subcommand */
        int has_subcmd = 0;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "install") == 0) {
                result = run_scheduler_install();
                has_subcmd = 1;
                break;
            } else if (strcmp(argv[i], "remove") == 0) {
                result = run_scheduler_remove();
                has_subcmd = 1;
                break;
            }
        }
        if (!has_subcmd) {
            result = run_scheduler();
        }
    } else if (strcmp(command, "alert-test") == 0) {
        result = run_alert_test();
    } else if (strcmp(command, "config") == 0) {
        result = run_config_tool();
    } else if (strcmp(command, "help") == 0) {
        print_usage(argv[0]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        result = 1;
    }
    
    /* Cleanup */
    log_close();
    
    if (signal_received) {
        printf(COLOR_YELLOW "\nInterrupted by signal %d\n" COLOR_RESET, signal_received);
    }
    
    return result;
}
