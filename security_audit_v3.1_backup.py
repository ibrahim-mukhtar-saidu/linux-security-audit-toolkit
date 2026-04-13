#!/usr/bin/env python3

import os
import platform
import socket
import subprocess
import datetime
import pwd


VERSION = "3.1"
AUTHOR = "Ibrahim Mukhtar Saidu"

REPORT = "reports/security_audit_report.txt"


PORT_INFO = {
    22: "SSH Remote Access",
    53: "DNS Service",
    80: "HTTP Web Service",
    443: "HTTPS Web Service",
    631: "CUPS Printing Service",
    5353: "mDNS Network Discovery",
    9050: "Tor Proxy Service"
}


SERVICE_INFO = {
    "ssh": "Remote administration service",
    "docker": "Container management service",
    "bluetooth": "Wireless communication service",
    "cups": "Printing service",
    "avahi": "Network discovery service",
    "tor": "Anonymous network service",
    "mysql": "Database service"
}



def banner():

    print("=" * 50)
    print(" CyberNova Linux Security Audit Toolkit")
    print("              Version 3.1")
    print("=" * 50)



def get_system_info():

    return f"""
System Information
------------------------------
Operating System: {platform.system()}
OS Release: {platform.release()}
Kernel Version: {platform.version()}
Hostname: {socket.gethostname()}
Current User: {os.getenv('USER')}
"""



def get_users():

    users = []

    for user in pwd.getpwall():

        users.append(user.pw_name)

    return users



def get_services():

    services = []

    try:

        result = subprocess.check_output(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running"
            ],
            text=True
        )


        for line in result.splitlines():

            if ".service" in line:

                services.append(
                    line.split()[0]
                )

    except:

        pass


    return services
def get_ports():

    ports = []

    try:

        result = subprocess.check_output(
            "ss -tulnp",
            shell=True,
            text=True
        )


        for line in result.splitlines():

            if ":" in line:

                try:

                    address = line.split()[4]

                    port = address.split(":")[-1]


                    if port.isdigit():

                        ports.append(int(port))


                except:

                    pass


    except:

        pass


    return sorted(list(set(ports)))




def check_world_writable():

    findings = []


    for directory in ["/tmp", "/var/tmp"]:

        try:

            for root, dirs, files in os.walk(directory):

                for file in files:

                    path = os.path.join(root, file)


                    try:

                        permissions = os.stat(path).st_mode


                        if permissions & 0o002:

                            findings.append(path)


                    except:

                        pass


        except:

            pass



    return findings[:10]




def check_suid_files():

    files = []


    try:

        result = subprocess.check_output(
            "find /usr/bin /bin -perm -4000 2>/dev/null",
            shell=True,
            text=True
        )


        for item in result.splitlines():

            files.append(item)


    except:

        pass


    return files[:15]




def analyze_security(world_files, suid_files, ports):

    score = 100

    findings = []


    if world_files:

        score -= 15

        findings.append(
            "[WARNING] World writable files detected\n"
            "Risk: Files writable by all users can be modified."
        )


    if len(ports) > 5:

        score -= 10

        findings.append(
            "[INFO] Multiple listening ports detected\n"
            "Review unnecessary network services."
        )


    if suid_files:

        findings.append(
            "[INFO] SUID binaries detected\n"
            "Review privileged executables."
        )


    if score < 0:

        score = 0


    return score, findings

def create_report():

    scan_time = datetime.datetime.now()


    users = get_users()

    services = get_services()

    ports = get_ports()

    world_files = check_world_writable()

    suid_files = check_suid_files()


    score, findings = analyze_security(
        world_files,
        suid_files,
        ports
    )


    report = f"""
CyberNova Linux Security Audit Report
==================================================

Author: {AUTHOR}

Version: {VERSION}

Scan Time:
{scan_time}


{get_system_info()}


Local User Accounts
------------------------------
"""


    for user in users:

        report += f"- {user}\n"



    report += """

Running Services
------------------------------
"""


    for service in services:

        clean_name = service.replace(
            ".service",
            ""
        )

        description = SERVICE_INFO.get(
            clean_name,
            "System service"
        )

        report += f"- {service}\n"
        report += f"  {description}\n"



    report += """

Open Listening Ports
------------------------------
"""


    if ports:

        for port in ports:

            description = PORT_INFO.get(
                port,
                "Unknown service"
            )

            report += f"- {port}: {description}\n"

    else:

        report += "- No listening ports detected\n"



    report += """

World Writable Files
------------------------------
"""


    if world_files:

        for item in world_files:

            report += f"[WARNING] {item}\n"

    else:

        report += "[OK] No world writable files found\n"



    report += """

SUID Files
------------------------------
"""


    if suid_files:

        for item in suid_files:

            report += f"[INFO] {item}\n"

    else:

        report += "[OK] No SUID files found\n"



    report += """

Security Analysis
------------------------------
"""


    if findings:

        for finding in findings:

            report += finding + "\n\n"

    else:

        report += "[OK] No security issues detected\n"



    report += f"""

Security Score
------------------------------
{score}/100


Risk Level:
"""


    if score >= 80:

        report += "LOW RISK\n"

    elif score >= 50:

        report += "MEDIUM RISK\n"

    else:

        report += "HIGH RISK\n"



    with open(REPORT, "w") as file:

        file.write(report)



    print(report)

    print(
        f"\nReport saved: {REPORT}"
    )




if __name__ == "__main__":

    banner()

    create_report()
