# 🛡️ CyberNova Linux Security Audit Toolkit

A Python-based Linux security auditing tool designed to analyze system security posture, identify common security weaknesses, and generate automated security audit reports.

Part of the **CYBERNOVA AI Cybersecurity Portfolio**.

---

# 📌 Project Overview

CyberNova Linux Security Audit Toolkit simulates a basic Linux security assessment workflow used by security analysts and system administrators.

The tool collects system security information and analyzes common security risks including:

- System information
- User account configuration
- Running services
- Listening network ports
- World writable files
- SUID binaries
- Security configuration issues

This project demonstrates practical defensive security concepts including:

- Linux security auditing
- System hardening concepts
- Security assessment workflow
- Risk identification
- Automated reporting

Designed for:

- Cybersecurity learning
- Linux administration practice
- Blue Team training
- Security portfolio demonstration

---

# 🏗️ Architecture / Workflow


System Information Collection
|
v
User Account Analysis
|
v
Service Enumeration
|
v
Network Port Analysis
|
v
File Permission Auditing
|
v
Security Risk Analysis
|
v
Audit Report Generation


## Workflow Explanation

1. The tool collects Linux system information.
2. Local users and security settings are analyzed.
3. Running services and listening ports are reviewed.
4. File permissions and SUID binaries are checked.
5. Security risks are classified.
6. An automated audit report is generated.

---

# 🚀 Features

✅ System information collection

✅ Linux user enumeration

✅ Running service analysis

✅ Listening port detection

✅ World writable file detection

✅ SUID binary auditing

✅ Security risk identification

✅ Security score calculation

✅ Automated audit report generation

✅ Clean terminal output

---

# 🔎 Security Checks Performed

The toolkit analyzes:

| Check | Purpose |
|---|---|
| User Accounts | Identify local account information |
| Services | Review active system services |
| Listening Ports | Detect exposed network services |
| File Permissions | Identify risky writable files |
| SUID Files | Detect privileged binaries |
| System Information | Understand system security posture |

---

# 🛠️ Technologies Used

- Python 3
- Linux
- psutil
- System Administration
- Linux Command Line
- File Permission Analysis
- Git/GitHub
- Unit Testing

---

# 📂 Project Structure


linux-security-audit-toolkit/

├── security_audit.py
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore

├── docs/
│ └── architecture.md

├── tests/
│ └── test_security_audit.py

├── sample_data/
│ └── sample_system.txt

├── reports/
│ └── security_audit_report.txt

└── screenshots/
└── version-3.1-security-audit.png


---

# ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/ibrahim-mukhtar-saidu/linux-security-audit-toolkit.git

Enter the project directory:

cd linux-security-audit-toolkit

Create virtual environment:

python3 -m venv venv

Activate:

source venv/bin/activate

Install requirements:

pip install -r requirements.txt
▶️ Usage

Run:

python3 security_audit.py

Example output:

CyberNova Linux Security Audit Toolkit

System Information Collected

Users Checked: 5

Running Services Checked: 42

Listening Ports Found: 3

Security Risks Detected: 2

Security Score: 85/100

Report saved:
reports/security_audit_report.txt
📄 Example Audit Findings

Example:

Security Audit Results

[MEDIUM]
World writable file detected:
/tmp/example.conf

[LOW]
Unused service detected:
example-service

Security Score:
85/100
🧪 Testing

Run:

python3 -m unittest discover -s tests

Example:

Ran 2 tests

OK
⚠️ Limitations

This project is designed as a learning tool.

Current limitations:

Does not automatically fix vulnerabilities
Does not replace enterprise security scanners
Uses basic security checks
Does not perform CVE vulnerability scanning
Requires authorized system access
🔐 Security and Ethical Disclaimer

This project is created for educational purposes and authorized security assessments only.

Only audit systems that you own or have explicit permission to analyze.

Unauthorized security testing may violate laws and security policies.

🔮 Future Improvements

Possible future upgrades:

Add JSON report export
Add HTML dashboard reports
Add CVE vulnerability database integration
Add CIS benchmark checks
Add automated remediation suggestions
Add SIEM integration
Add scheduled security scans
Add compliance reporting
👨‍💻 Author

Ibrahim Mukhtar Saidu

Cybersecurity Portfolio Project

CYBERNOVA AI

📜 License

MIT License
