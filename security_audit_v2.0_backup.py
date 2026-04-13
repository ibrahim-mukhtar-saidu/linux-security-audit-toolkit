"""
CyberNova Linux Security Audit Toolkit

Version: 2.0
Author: Ibrahim Mukhtar Saidu

A beginner-friendly Linux security auditing toolkit that collects
system information, user accounts, running services, open listening
ports, and basic security recommendations.
"""

import platform
import socket
import getpass
import subprocess
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


def get_running_services():
    services = []
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            if ".service" in line:
                services.append(line.split()[0].replace(".service", ""))
    except Exception:
        services.append("Unable to retrieve running services")
    return services


def get_open_ports():
    ports = []
    try:
        result = subprocess.run(
            ["ss", "-tuln"],
            capture_output=True,
            text=True,
        )

        for line in result.stdout.splitlines():
            if "LISTEN" in line:
                parts = line.split()
                if len(parts) >= 5:
                    address = parts[4]

                    # Extract the port number from IPv4, IPv6, or wildcard addresses
                    if ":" in address:
                        port = address.rsplit(":", 1)[-1]
                        if port.isdigit() and port not in ports:
                            ports.append(port)

    except Exception:
        ports.append("Unable to retrieve open ports")

    return ports


def generate_recommendations(services, ports):
    recommendations = []
    score = 100

    if "ssh" in services or "sshd" in services:
        recommendations.append("[WARNING] SSH service is running; verify secure configuration.")
        score -= 10

    if "9050" in ports:
        recommendations.append("[INFO] Tor service detected (port 9050).")

    if len(ports) > 10:
        recommendations.append("[WARNING] Multiple listening ports detected; review exposed services.")
        score -= 10

    if not recommendations:
        recommendations.append("[OK] No obvious security concerns detected by this basic audit.")

    return recommendations, max(score, 0)


def save_report(system_info, users, services, ports, recommendations, score):
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

        report.write("\nRunning Services\n")
        report.write("-" * 30 + "\n")
        for service in services[:20]:
            report.write(f"- {service}\n")

        report.write("\nOpen Listening Ports\n")
        report.write("-" * 30 + "\n")
        for port in ports:
            report.write(f"- {port}\n")

        report.write("\nSecurity Recommendations\n")
        report.write("-" * 30 + "\n")
        for item in recommendations:
            report.write(f"{item}\n")

        report.write(f"\nSecurity Score: {score}/100\n")


def main():
    print("=" * 50)
    print("   CyberNova Linux Security Audit Toolkit")
    print("               Version 2.0")
    print("=" * 50)

    system_info = get_system_info()
    users = get_local_users()
    services = get_running_services()
    ports = get_open_ports()
    recommendations, score = generate_recommendations(services, ports)

    print("\nSystem Information")
    print("-" * 30)
    for key, value in system_info.items():
        print(f"{key}: {value}")

    print("\nRunning Services")
    print("-" * 30)
    for service in services[:10]:
        print(service)

    print("\nOpen Listening Ports")
    print("-" * 30)
    if ports:
        for port in ports:
            print(port)
    else:
        print("No listening ports detected")

    print("\nSecurity Recommendations")
    print("-" * 30)
    for item in recommendations:
        print(item)

    print(f"\nSecurity Score: {score}/100")

    save_report(system_info, users, services, ports, recommendations, score)

    print("\nReport saved: reports/security_audit_report.txt")


if __name__ == "__main__":
    main()
