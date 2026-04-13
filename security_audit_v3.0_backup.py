import os
import platform
import socket
import subprocess
from datetime import datetime
from pathlib import Path


AUTHOR = "Ibrahim Mukhtar Saidu"


def get_system_info():
    return {
        "Operating System": platform.system(),
        "OS Release": platform.release(),
        "Kernel Version": platform.version(),
        "Hostname": socket.gethostname(),
        "Current User": os.getlogin()
    }


def get_users():
    users = []

    try:
        with open("/etc/passwd", "r") as file:
            for line in file:
                users.append(line.split(":")[0])
    except Exception:
        pass

    return users


def get_services():
    services = []

    try:
        result = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--state=running"],
            text=True
        )

        for line in result.splitlines():
            if ".service" in line:
                services.append(line.split()[0])

    except Exception:
        pass

    return services[:20]


def get_open_ports():
    ports = []

    try:
        result = subprocess.check_output(
            ["ss", "-tuln"],
            text=True
        )

        for line in result.splitlines()[1:]:
            parts = line.split()

            if len(parts) >= 5:
                address = parts[4]

                if ":" in address:
                    port = address.split(":")[-1]

                    if port.isdigit():
                        ports.append(port)

    except Exception:
        pass

    return list(set(ports))


def find_world_writable_files():
    findings = []

    locations = [
        "/tmp",
        "/var/tmp"
    ]

    for location in locations:
        if os.path.exists(location):

            for root, dirs, files in os.walk(location):

                for file in files:
                    path = os.path.join(root, file)

                    try:
                        permissions = os.stat(path).st_mode

                        if permissions & 0o002:
                            findings.append(path)

                    except Exception:
                        pass

    return findings[:10]


def find_suid_files():
    findings = []

    try:
        result = subprocess.check_output(
            "find /usr/bin -perm -4000 2>/dev/null",
            shell=True,
            text=True
        )

        findings = result.splitlines()[:10]

    except Exception:
        pass

    return findings


def calculate_score(world_files, suid_files):

    score = 100

    score -= len(world_files) * 5
    score -= len(suid_files) * 2

    if score < 0:
        score = 0

    return score


def save_report(info, users, services, ports, world_files, suid_files, score):

    report = "CyberNova Linux Security Audit Report\n"
    report += "=" * 50 + "\n\n"

    report += f"Author: {AUTHOR}\n"
    report += f"Scan Time: {datetime.now()}\n\n"


    report += "System Information\n"
    report += "-" * 30 + "\n"

    for key, value in info.items():
        report += f"{key}: {value}\n"


    report += "\nRunning Services\n"
    report += "-" * 30 + "\n"

    for service in services:
        report += f"- {service}\n"


    report += "\nOpen Listening Ports\n"
    report += "-" * 30 + "\n"

    for port in ports:
        report += f"- {port}\n"


    report += "\nWorld Writable Files\n"
    report += "-" * 30 + "\n"

    if world_files:
        for item in world_files:
            report += f"[WARNING] {item}\n"
    else:
        report += "No world writable files found.\n"


    report += "\nSUID Files\n"
    report += "-" * 30 + "\n"

    if suid_files:
        for item in suid_files:
            report += f"[INFO] {item}\n"
    else:
        report += "No SUID files detected.\n"


    report += "\nSecurity Score\n"
    report += "-" * 30 + "\n"
    report += f"{score}/100\n"


    with open("reports/security_audit_report.txt", "w") as file:
        file.write(report)


def main():

    print("=" * 50)
    print("   CyberNova Linux Security Audit Toolkit")
    print("               Version 3.0")
    print("=" * 50)


    info = get_system_info()

    print("\nSystem Information")
    print("-" * 30)

    for key, value in info.items():
        print(f"{key}: {value}")


    print("\nRunning Services")
    print("-" * 30)

    services = get_services()

    for service in services:
        print(service)


    print("\nOpen Listening Ports")
    print("-" * 30)

    ports = get_open_ports()

    for port in ports:
        print(port)


    print("\nSecurity Analysis")
    print("-" * 30)

    world_files = find_world_writable_files()
    suid_files = find_suid_files()

    if world_files:
        print("[WARNING] World writable files detected")
    else:
        print("[OK] No world writable files found")


    score = calculate_score(world_files, suid_files)

    print("\nSecurity Score:", score, "/100")


    save_report(
        info,
        get_users(),
        services,
        ports,
        world_files,
        suid_files,
        score
    )


    print("\nReport saved: reports/security_audit_report.txt")


if __name__ == "__main__":
    main()
