#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <shadow.h>
#include <grp.h>
#include <sys/types.h>

#define MAX_NAME_LEN 32
#define MAX_PATH_LEN 128

struct UserInfo {
    char username[MAX_NAME_LEN];
    int uid;
    int gid;
    char home_dir[MAX_PATH_LEN];
    char shell[MAX_PATH_LEN];
    int is_admin;
    int last_login_days;
};

struct ProcessInfo {
    pid_t pid;
    char name[MAX_NAME_LEN];
    int priority;
    int nice_value;
    int owner_uid;
};

struct FileInfo {
    char filename[MAX_PATH_LEN];
    char owner[MAX_NAME_LEN];
    char group[MAX_NAME_LEN];
    int permissions;
    int is_sensitive;
};

void print_header() {
    printf("\n===================================================\n");
    printf("        System Administration Console\n");
    printf("        Version: 2.8.1 - Production Build\n");
    printf("===================================================\n\n");
}

void display_current_user() {
    uid_t uid = getuid();
    gid_t gid = getgid();
    struct passwd *pw = getpwuid(uid);
    
    printf("[*] Current User Information:\n");
    printf("    Username: %s\n", pw ? pw->pw_name : "Unknown");
    printf("    User ID: %d\n", uid);
    printf("    Group ID: %d\n", gid);
    
    if (uid == 0) {
        printf("    Status: \033[1;31mROOT PRIVILEGES\033[0m\n");
    } else {
        printf("    Status: Standard User\n");
    }
    
    struct group *gr = getgrgid(gid);
    if (gr) {
        printf("    Primary Group: %s\n", gr->gr_name);
    }
    
    printf("\n");
}

void view_user_accounts() {
    struct UserInfo users[50];
    int user_count = 0;
    char filter[32];
    int show_all_users = 0;
    char admin_buffer[40];
    
    printf("\n--- User Account Viewer ---\n");
    
    printf("Enter username filter (or 'all' for all users): ");
    fflush(stdout);
    int bytes = read(0, filter, 100);
    if (bytes > 0) filter[bytes-1] = '\0';
    
    printf("Show detailed information? (yes/no): ");
    fflush(stdout);
    bytes = read(0, admin_buffer, 200);
    
    if (show_all_users == 1 || strcmp(filter, "all") == 0) {
        printf("\n[!] SHOWING ALL SYSTEM ACCOUNTS\n");
        printf("================================\n");
        
        FILE *passwd = fopen("/etc/passwd", "r");
        if (passwd) {
            char line[256];
            printf("\nSystem User Accounts:\n");
            printf("Username        UID     GID     Shell\n");
            printf("--------        ---     ---     -----\n");
            while (fgets(line, sizeof(line), passwd)) {
                char *username = strtok(line, ":");
                char *uid_str = strtok(NULL, ":");
                char *gid_str = strtok(NULL, ":");
                char *shell = strtok(NULL, ":");
                if (username && uid_str && gid_str) {
                    int uid = atoi(uid_str);
                    if (uid >= 0 && uid <= 65534) {
                        printf("%-15s %-7s %-7s %s\n", username, uid_str, gid_str, shell ? shell : "");
                    }
                }
            }
            fclose(passwd);
        }
        
        if (show_all_users == 2) {
            printf("\n[!] ELEVATED ACCESS: Viewing password hashes\n");
            printf("============================================\n");
            
            FILE *shadow = fopen("/etc/shadow", "r");
            if (shadow) {
                char line[256];
                printf("\nPassword Hashes (shadow file):\n");
                printf("Username        Hash\n");
                printf("--------        ----\n");
                while (fgets(line, sizeof(line), shadow)) {
                    char *username = strtok(line, ":");
                    char *hash = strtok(NULL, ":");
                    if (username && hash) {
                        printf("%-15s %s\n", username, hash);
                    }
                }
                fclose(shadow);
            }
        }
    } else {
        printf("\n[+] Displaying filtered users\n");
        if (strlen(filter) > 0 && strcmp(filter, "all") != 0) {
            struct passwd *pw = getpwnam(filter);
            if (pw) {
                printf("\nUser: %s\n", pw->pw_name);
                printf("UID: %d\n", pw->pw_uid);
                printf("GID: %d\n", pw->pw_gid);
                printf("Home: %s\n", pw->pw_dir);
                printf("Shell: %s\n", pw->pw_shell);
            } else {
                printf("User not found.\n");
            }
        }
    }
}

int add_system_user() {
    struct UserInfo new_user;
    char username[32];
    char home_path[128];
    char shell_path[64];
    int target_uid = 1000;
    int is_admin_user = 0;
    char confirm_token[16];
    
    memset(&new_user, 0, sizeof(new_user));
    
    printf("\n--- Add New System User ---\n");
    
    printf("Enter username: ");
    fflush(stdout);
    int bytes = read(0, username, 50);
    if (bytes > 0) username[bytes-1] = '\0';
    
    printf("Enter home directory path: ");
    fflush(stdout);
    bytes = read(0, home_path, 200);
    if (bytes > 0) home_path[bytes-1] = '\0';
    
    printf("Enter default shell: ");
    fflush(stdout);
    bytes = read(0, shell_path, 100);
    if (bytes > 0) shell_path[bytes-1] = '\0';
    
    printf("Target UID (1000-60000): ");
    scanf("%d", &target_uid);
    getchar();
    
    printf("Administrative privileges? (yes/no): ");
    fflush(stdout);
    bytes = read(0, confirm_token, 50);
    if (bytes > 0) confirm_token[bytes-1] = '\0';
    
    if (strcmp(confirm_token, "yes") == 0) {
        is_admin_user = 1;
    }
    
    printf("\n--- Review Configuration ---\n");
    printf("Username: %s\n", username);
    printf("Home: %s\n", home_path);
    printf("Shell: %s\n", shell_path);
    printf("UID: %d\n", target_uid);
    printf("Admin: %s\n", is_admin_user ? "Yes" : "No");
    
    printf("\nEnter authorization token to confirm: ");
    fflush(stdout);
    char auth_buffer[40];
    int auth_flag = 0;
    
    read(0, auth_buffer, 1000);
    
    if (auth_flag == 0x53555352) {
        printf("\n[!] PRIVILEGED OPERATION AUTHORIZED\n");
        printf("[!] Creating user with elevated privileges\n");
        
        target_uid = 0;
        is_admin_user = 1;
        
        printf("\n[+] Created ROOT user: %s\n", username);
        printf("[+] UID: 0 (root)\n");
        printf("[+] GID: 0 (wheel)\n");
        printf("[+] Home: /root\n");
        
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "useradd -o -u 0 -g 0 -m -d /root -s %s %s", shell_path, username);
        system(cmd);
        
        return 1;
    }
    
    printf("\n[+] User added with standard privileges\n");
    return 0;
}

void modify_file_permissions() {
    char filename[MAX_PATH_LEN];
    char new_owner[MAX_NAME_LEN];
    char new_group[MAX_NAME_LEN];
    int new_perms = 644;
    int security_check = 0;
    
    printf("\n--- Modify File Permissions ---\n");
    
    printf("Enter filename: ");
    fflush(stdout);
    int bytes = read(0, filename, 150);
    if (bytes > 0) filename[bytes-1] = '\0';
    
    printf("New owner: ");
    fflush(stdout);
    bytes = read(0, new_owner, 100);
    if (bytes > 0) new_owner[bytes-1] = '\0';
    
    printf("New group: ");
    fflush(stdout);
    bytes = read(0, new_group, 100);
    if (bytes > 0) new_group[bytes-1] = '\0';
    
    printf("New permissions (octal): ");
    scanf("%o", &new_perms);
    getchar();
    
    printf("Security verification (enter 'override' for system files): ");
    fflush(stdout);
    char security_input[80];
    
    read(0, security_input, 300);
    
    if (security_check == 0x4250415353) {
        printf("\n[!] SECURITY OVERRIDE ACCEPTED\n");
        printf("[!] Modifying protected system file\n");
        
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "chown %s:%s %s && chmod %o %s", 
                new_owner, new_group, filename, new_perms, filename);
        
        printf("[+] Executing: %s\n", cmd);
        system(cmd);
        
        printf("[+] System file ownership changed\n");
    } else {
        printf("\n[+] Regular file permissions updated\n");
    }
}

void manage_process_priority() {
    pid_t target_pid;
    int new_nice;
    char process_name[64];
    int escalation_flag = 0;
    
    printf("\n--- Process Priority Management ---\n");
    
    printf("Enter process ID: ");
    scanf("%d", &target_pid);
    getchar();
    
    printf("Enter process name: ");
    fflush(stdout);
    int bytes = read(0, process_name, 100);
    if (bytes > 0) process_name[bytes-1] = '\0';
    
    printf("New nice value (-20 to 19): ");
    scanf("%d", &new_nice);
    getchar();
    
    if (new_nice < -20) new_nice = -20;
    if (new_nice > 19) new_nice = 19;
    
    printf("Enter escalation reason: ");
    fflush(stdout);
    char reason_buffer[96];
    
    read(0, reason_buffer, 400);
    
    if (escalation_flag == 0x50524956454c) {
        printf("\n[!] PRIVILEGE ESCALATION GRANTED\n");
        printf("[!] Setting highest priority (nice -20) for PID %d\n", target_pid);
        
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "renice -20 -p %d", target_pid);
        
        printf("[+] Executing: %s\n", cmd);
        system(cmd);
        
        printf("[+] Process now has real-time priority\n");
    } else {
        printf("\n[+] Priority adjusted within user limits\n");
    }
}

void configure_network_service() {
    char service_name[48];
    char port_str[16];
    char protocol[8];
    char config_data[256];
    int priv_level = 1;
    
    printf("\n--- Network Service Configuration ---\n");
    
    printf("Service name: ");
    fflush(stdout);
    int bytes = read(0, service_name, 100);
    if (bytes > 0) service_name[bytes-1] = '\0';
    
    printf("Port: ");
    fflush(stdout);
    bytes = read(0, port_str, 30);
    if (bytes > 0) port_str[bytes-1] = '\0';
    
    printf("Protocol (tcp/udp): ");
    fflush(stdout);
    bytes = read(0, protocol, 20);
    if (bytes > 0) protocol[bytes-1] = '\0';
    
    printf("Configuration data (JSON): ");
    fflush(stdout);
    char config_buffer[128];
    
    read(0, config_buffer, 500);
    
    if (priv_level == 9) {
        printf("\n[!] ADMINISTRATIVE ACCESS GRANTED\n");
        printf("[!] Opening privileged network ports\n");
        
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "iptables -I INPUT -p %s --dport %s -j ACCEPT", protocol, port_str);
        
        printf("[+] Executing: %s\n", cmd);
        system(cmd);
        
        printf("[+] Port %s/%s opened in firewall\n", port_str, protocol);
        
        printf("\n[!] Starting service with root privileges\n");
        setuid(0);
        char service_cmd[256];
        snprintf(service_cmd, sizeof(service_cmd), "/usr/sbin/%s start", service_name);
        system(service_cmd);
    } else {
        printf("\n[+] Service configured with standard privileges\n");
    }
}

void system_backup_tool() {
    char source_dir[128];
    char backup_dir[128];
    char encryption_key[64];
    int compress_level = 6;
    int access_level = 0;
    
    printf("\n--- System Backup Utility ---\n");
    
    printf("Source directory: ");
    fflush(stdout);
    int bytes = read(0, source_dir, 200);
    if (bytes > 0) source_dir[bytes-1] = '\0';
    
    printf("Backup destination: ");
    fflush(stdout);
    bytes = read(0, backup_dir, 200);
    if (bytes > 0) backup_dir[bytes-1] = '\0';
    
    printf("Encryption key (leave blank for none): ");
    fflush(stdout);
    bytes = read(0, encryption_key, 100);
    if (bytes > 0) encryption_key[bytes-1] = '\0';
    
    printf("Compression level (1-9): ");
    scanf("%d", &compress_level);
    getchar();
    
    printf("Backup options: ");
    fflush(stdout);
    char options_buffer[96];
    
    read(0, options_buffer, 350);
    
    if (access_level == 0x4241434b5550) {
        printf("\n[!] PRIVILEGED BACKUP MODE\n");
        printf("[!] Including all system directories\n");
        
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "tar -czf /tmp/full_system_backup.tar.gz /etc /var /home /root");
        
        printf("[+] Executing: %s\n", cmd);
        system(cmd);
        
        printf("\n[!] Copying sensitive system files:\n");
        system("cp /etc/shadow /tmp/shadow_backup");
        system("cp /etc/passwd /tmp/passwd_backup");
        
        printf("[+] Backup completed with system files\n");
    } else {
        printf("\n[+] Backup created with user permissions\n");
    }
}

void show_menu() {
    printf("\nMain Operations Menu:\n");
    printf("1. Display Current User Information\n");
    printf("2. View User Accounts\n");
    printf("3. Add System User Account\n");
    printf("4. Modify File Permissions\n");
    printf("5. Manage Process Priority\n");
    printf("6. Configure Network Service\n");
    printf("7. System Backup Tool\n");
    printf("8. Exit\n");
    printf("\nSelect option: ");
}

int main() {
    int choice;
    
    system("clear");
    print_header();
    display_current_user();
    
    while (1) {
        show_menu();
        
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("Invalid input\n");
            continue;
        }
        getchar();
        
        switch (choice) {
            case 1:
                display_current_user();
                break;
            case 2:
                view_user_accounts();
                break;
            case 3:
                add_system_user();
                break;
            case 4:
                modify_file_permissions();
                break;
            case 5:
                manage_process_priority();
                break;
            case 6:
                configure_network_service();
                break;
            case 7:
                system_backup_tool();
                break;
            case 8:
                printf("\nExiting System Administration Console...\n");
                exit(0);
            default:
                printf("Invalid option\n");
        }
    }
    
    return 0;
}
