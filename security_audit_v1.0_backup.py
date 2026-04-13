"""
CyberNova Linux Security Audit Toolkit

Version: 1.0
Author: Ibrahim Mukhtar Saidu

A beginner-friendly Linux security auditing toolkit that
collects basic system information and user account details.
"""

import platform
import socket
import getpass
from datetime import datetime


def get_system_info():
    return {
        "Operating System": platform.system(),
        "OS Release": platform.release(),
        "Kernel Version": platform.version(),
        "Hostname": socket.gethostname(),
        "Current User": getpass.getuser(),
    }


def get_local_users():
    users = []
    try:
        with open("/etc/passwd", "r") as passwd_file:
            for line in passwd_file:
                users.append(line.split(":")[0])
    except Exception:
        users.append("Unable to read /etc/passwd")
    return users


def save_report(system_info, users):
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("reports/security_audit_report.txt", "w") as report:
        report.write("CyberNova Linux Security Audit Report\n")
        report.write("=" * 50 + "\n")
        report.write(f"Author: Ibrahim Mukhtar Saidu\n")
        report.write(f"Scan Time: {scan_time}\n\n")

        report.write("System Information\n")
        report.write("-" * 30 + "\n")
        for key, value in system_info.items():
            report.write(f"{key}: {value}\n")

        report.write("\nLocal User Accounts\n")
        report.write("-" * 30 + "\n")
        for user in users:
            report.write(f"- {user}\n")


def main():
    print("=" * 50)
    print("   CyberNova Linux Security Audit Toolkit")
    print("               Version 1.0")
    print("=" * 50)

    system_info = get_system_info()
    users = get_local_users()

    print("\nSystem Information")
    print("-" * 30)
    for key, value in system_info.items():
        print(f"{key}: {value}")

    print("\nLocal User Accounts")
    print("-" * 30)
    for user in users[:10]:
        print(user)

    save_report(system_info, users)

    print("\nReport saved: reports/security_audit_report.txt")


if __name__ == "__main__":
    main()
