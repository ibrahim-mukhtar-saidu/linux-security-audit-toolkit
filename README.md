# 🛡️ CyberNova Linux Security Audit Toolkit

**A read-only Linux security auditing toolkit for security posture assessment, defensive analysis, and authorized security testing.**

[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](#requirements)
[![Tests](https://img.shields.io/badge/Tests-110%20passed-brightgreen.svg)](#testing)
[![Coverage](https://img.shields.io/badge/Coverage-99%25-brightgreen.svg)](#testing)
[![Security](https://img.shields.io/badge/Bandit-0%20findings-brightgreen.svg)](#security-validation)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Part of the **CYBERNOVA AI Cybersecurity Portfolio** by **Ibrahim Mukhtar Saidu**.

---

## 📌 Overview

CyberNova Linux Security Audit Toolkit is a Python-based defensive security tool designed to assess the security posture of a Linux host through a collection of read-only security checks.

The toolkit gathers normalized host evidence, analyzes common security conditions, calculates a security score, identifies findings, and generates a human-readable audit report.

The project focuses on practical defensive security engineering rather than exploitation.

### Security assessment areas

* System information
* Local user accounts
* Running system services
* Listening network ports
* World-writable files
* SUID binaries
* Collection failures and incomplete evidence
* Security risk analysis
* Security scoring
* Audit report generation

---

## 🎯 Project Goals

This project demonstrates practical capability in:

* Linux security auditing
* Defensive security engineering
* Host-based security assessment
* Evidence collection and normalization
* Secure subprocess execution
* Input and parser validation
* Error handling
* Security risk classification
* Automated security reporting
* Python type safety
* Automated security testing
* Static analysis
* Dependency vulnerability auditing
* Adversarial validation

The toolkit is intentionally designed as a **learning, laboratory, and portfolio security project**, not as a replacement for enterprise vulnerability-management or endpoint-security platforms.

---

## 🏗️ Architecture

```text
                    Linux Host
                        │
                        ▼
              ┌─────────────────────┐
              │ Evidence Collection │
              └──────────┬──────────┘
                         │
       ┌─────────────────┼─────────────────┐
       │                 │                 │
       ▼                 ▼                 ▼
 System Information   Users          Services
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
       Listening Ports      File Permissions
              │                     │
              │              ┌──────┴──────┐
              │              │             │
              │              ▼             ▼
              │       World-Writable     SUID
              │          Files           Files
              │              │             │
              └──────────────┼─────────────┘
                             ▼
                  ┌─────────────────────┐
                  │ Security Analysis   │
                  │                     │
                  │ Findings            │
                  │ Risk Level          │
                  │ Security Score      │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Audit Report        │
                  │                     │
                  │ UTC Timestamp        │
                  │ Evidence             │
                  │ Findings             │
                  │ Risk Assessment      │
                  └─────────────────────┘
```

### Collection model

The toolkit separates evidence collection from security analysis.

Each collection operation returns structured results containing:

* collected values
* command information where applicable
* return status
* collection errors

This prevents command failures from being silently discarded and allows incomplete evidence to be represented explicitly.

---

## 🔎 Security Checks

| Check                | Purpose                                                                          |
| -------------------- | -------------------------------------------------------------------------------- |
| System Information   | Establish basic host and operating-system context                                |
| User Accounts        | Enumerate local user accounts                                                    |
| Running Services     | Identify active system services                                                  |
| Listening Ports      | Identify locally listening TCP/UDP ports                                         |
| World-Writable Files | Detect regular files writable by other users in configured temporary directories |
| SUID Files           | Identify regular SUID files in configured system directories                     |
| Collection Errors    | Record failed or incomplete evidence collection                                  |
| Security Analysis    | Convert collected evidence into findings and a risk assessment                   |
| Security Score       | Produce a deterministic 0–100 security score                                     |
| Audit Report         | Generate a timestamped human-readable report                                     |

### Listening-port parsing

Network-port parsing is designed to tolerate variations in `ss` output rather than relying on one fixed column position.

The parser:

* handles IPv4 endpoints
* handles IPv6 endpoints
* handles wildcard addresses
* rejects invalid ports
* rejects ports outside `1–65535`
* ignores malformed records
* deduplicates discovered ports

### File-permission auditing

World-writable checks:

* inspect configured temporary directories
* avoid following directory symlinks
* consider regular files only
* tolerate permission/race-related filesystem errors
* limit returned findings to prevent unbounded collection

### SUID auditing

SUID discovery:

* uses `find` through an argument array
* does **not** invoke a shell
* validates configured directories
* handles command failures explicitly
* limits collected results

---

## 🔐 Security Engineering

The project was hardened against several classes of implementation risk.

### Secure command execution

External Linux utilities are executed using argument arrays rather than shell command strings.

```python
subprocess.run(
    command_tuple,
    capture_output=True,
    text=True,
    check=False,
    timeout=timeout,
)
```

The toolkit does not use `shell=True` for its system commands.

### Command timeouts

External commands have a bounded execution time to prevent an unresponsive system utility from indefinitely blocking the audit.

### Explicit exception handling

Broad `except:` handlers were removed.

Expected operating-system and subprocess failures are handled explicitly and represented as collection errors where appropriate.

### Authoritative user identification

The current user is obtained from the process UID rather than trusting the `$USER` environment variable.

### UTC timestamps

Generated audit reports use timezone-aware UTC timestamps.

### Deterministic report location

The default report path is resolved relative to the project location rather than depending on the caller's current working directory.

### Parser hardening

Network output is treated as untrusted input and parsed defensively.

Malformed, empty, invalid, and out-of-range values are rejected without crashing the audit.

---

## 📊 Security Scoring

The toolkit calculates a security score from collected evidence.

The score is accompanied by a risk classification:

|  Score | Risk Level    |
| -----: | ------------- |
| 90–100 | LOW RISK      |
|  70–89 | MODERATE RISK |
|  40–69 | HIGH RISK     |
|   0–39 | CRITICAL RISK |

The score is intended as a **laboratory assessment indicator**, not as a standardized enterprise security rating.

Collection failures are also considered so that incomplete evidence does not appear equivalent to a fully successful audit.

---

## 📁 Project Structure

```text
linux-security-audit-toolkit/
├── .gitignore
├── LICENSE
├── README.md
├── docs/
│   └── architecture.md
├── main.py
├── requirements.txt
├── security_audit.py
├── sample_data/
│   └── sample_system.txt
├── reports/
│   └── security_audit_report.txt
├── screenshots/
│   └── version-3.1-security-audit.png
└── tests/
    └── test_security_audit.py
```

### Important repository hygiene

Generated Python bytecode, virtual environments, pytest caches, and coverage artifacts are excluded from version control.

The project currently has **no third-party runtime dependency**.

`requirements.txt` is intentionally empty because the hardened implementation uses Python's standard library and installed system utilities.

---

## ⚙️ Requirements

### Operating system

* Linux
* Python 3.13+ recommended

### System utilities

The toolkit can use standard Linux utilities including:

* `systemctl`
* `ss`
* `find`

Availability depends on the target Linux distribution and environment.

### Python dependencies

No third-party runtime package is currently required.

For development and validation, the project uses tools including:

* pytest
* pytest-cov
* Ruff
* Bandit
* MyPy
* pip-audit

These are development/security-validation tools rather than application runtime dependencies.

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/ibrahim-mukhtar-saidu/linux-security-audit-toolkit.git
cd linux-security-audit-toolkit
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

The application has no third-party runtime dependencies.

For development and testing, install the required validation tools in the virtual environment.

---

## ▶️ Usage

### Show version

```bash
python main.py --version
```

Example:

```text
CyberNova Linux Security Audit Toolkit v3.2
```

### Show help

```bash
python main.py --help
```

### Run a complete audit

```bash
python main.py --audit
```

The audit collects host information, performs the configured security checks, analyzes the collected evidence, and writes the audit report.

The default report is generated at:

```text
reports/security_audit_report.txt
```

The report includes a timezone-aware UTC audit timestamp.

---

## 📄 Audit Report

A generated report contains sections covering:

```text
System Information
Local User Accounts
Running Services
Listening Network Ports
World-Writable Files
SUID Files
Security Analysis
Security Score
Risk Level
Findings
```

Example structure:

```text
============================================================
CYBERNOVA LINUX SECURITY AUDIT TOOLKIT
============================================================
Version: 3.2
Author: Ibrahim Mukhtar Saidu
Audit Timestamp (UTC): ...

SYSTEM INFORMATION
------------------
OS: Linux
OS Release: ...
Kernel: ...
Hostname: ...
Current User: ...

SECURITY ANALYSIS
-----------------
Security Score: 90/100
Risk Level: LOW RISK

FINDINGS
--------
...
```

---

## 🧪 Testing

The project contains a comprehensive automated test suite covering normal behavior, error conditions, malformed input, security boundaries, and reporting.

Run the complete test suite:

```bash
python -m pytest -q
```

Current validation result:

```text
110 passed
```

### Coverage

Run:

```bash
python -m pytest \
    --cov=security_audit \
    --cov-report=term-missing \
    -q
```

Current coverage:

```text
99%
```

The project intentionally targets **at least 95% coverage** rather than adding artificial tests solely to reach 100%.

---

## 🔍 Static Analysis

### Ruff

```bash
python -m ruff check .
python -m ruff format --check .
```

Current result:

```text
All checks passed!
5 files already formatted
```

### MyPy

```bash
python -m mypy security_audit.py main.py
```

Current result:

```text
Success: no issues found in 2 source files
```

---

## 🔒 Security Validation

### Bandit

The application code is scanned using Bandit:

```bash
python -m bandit -r . -x ./venv,./.git,./htmlcov,./tests
```

Current result:

```text
No issues identified.
```

Intentional Bandit exceptions are limited to:

* controlled use of Python `subprocess`
* intentional auditing of `/tmp` and `/var/tmp`

The subprocess implementation uses argument arrays rather than shell command strings.

### Dependency audit

```bash
python -m pip_audit
```

Current result:

```text
No known vulnerabilities found
```

### Compilation validation

```bash
python -m compileall -q .
```

The source compiles successfully.

### Git integrity

```bash
git diff --check
```

The repository passes whitespace/error checking.

---

## 🧨 Adversarial Validation

The hardened implementation was also tested against security-focused edge cases.

### Command-injection resistance

A payload containing shell metacharacters was supplied as a command argument.

Result:

```text
injection_file_exists=False
```

The payload remained data rather than becoming a shell command.

### Malformed network data

Malformed `ss` records were supplied to the parser.

Invalid records were rejected while valid data was retained.

### Port boundaries

The parser rejects:

```text
0
65536
-1
abc
""
```

while accepting valid ports such as:

```text
1
65535
```

### Collection failures

Simulated command failures are returned as structured collection errors rather than silently disappearing.

### Collection limits

World-writable and SUID result collection is bounded to prevent uncontrolled result growth.

### Source regression checks

The hardened source was verified to contain none of the following patterns:

```text
shell=True
bare except
datetime.datetime.now()
os.getenv("USER")
```

---

## 🧠 Engineering Decisions

### Read-only by default

The toolkit is designed to inspect the host rather than modify system configuration.

It does not automatically:

* disable services
* change permissions
* remove users
* modify firewall rules
* delete files
* remediate vulnerabilities

This reduces the risk of unintended system changes during assessment.

### Evidence before analysis

Collection and analysis are separated so that security conclusions can be derived from normalized evidence.

### Fail visibly

Collection errors are represented explicitly rather than silently ignored.

This is important because a failed check should not be interpreted as proof that no security issue exists.

### Bounded collection

Filesystem and SUID checks limit returned results to avoid unbounded memory or report growth.

### Secure subprocess handling

External commands are executed without shell interpretation and with bounded execution time.

### Standard-library implementation

The current application does not require external Python runtime packages, reducing dependency and supply-chain exposure.

---

## 🛡️ Threat Model

The toolkit operates under the assumption that it is executed by an authorized user against a Linux host they own or are explicitly permitted to assess.

Potentially untrusted inputs include:

* operating-system command output
* network socket listings
* filesystem metadata
* malformed command output
* unexpected usernames and filenames
* unusual or corrupted system state

The implementation therefore emphasizes:

* defensive parsing
* bounded collection
* explicit failures
* secure subprocess invocation
* deterministic reporting
* no automatic remediation

---

## ⚠️ Limitations

This project is a **security auditing and laboratory toolkit**, not a production enterprise security platform.

Current limitations include:

* It performs a limited set of host-security checks.
* It does not perform comprehensive vulnerability or CVE scanning.
* It does not implement full CIS benchmark compliance.
* It does not replace enterprise endpoint-security platforms.
* It does not provide continuous monitoring.
* It does not provide 24/7 SOC operations.
* It does not perform automatic remediation.
* It does not provide enterprise-scale asset management.
* It does not provide production SIEM correlation.
* Security scoring is a project-specific assessment model, not an industry-standard rating.
* Results depend on the availability and behavior of Linux system utilities.
* Some system information and security checks may require appropriate privileges depending on the target environment.

### Professional scope

This repository demonstrates **hands-on defensive security engineering and Linux security auditing experience in a controlled laboratory/project environment**.

It should not be represented as evidence of production SOC employment, enterprise incident-response authority, or commercial security operations experience.

---

## 🔐 Ethical Use

Use this toolkit only on:

* systems you own
* systems you administer
* authorized laboratory environments
* systems for which you have explicit permission to perform security auditing

Do not use it to inspect systems without authorization.

The author is not responsible for misuse of the project.

---

## 🔮 Future Development

Potential future enhancements include:

* JSON report generation
* HTML reporting
* CIS benchmark checks
* additional Linux hardening checks
* CVE/database integration
* remediation recommendations
* scheduled auditing
* SIEM integration
* compliance-oriented reporting
* configurable scoring policies
* additional platform support

Future functionality should preserve the project's read-only and security-first design principles.

---

## 👨‍💻 Author

**Ibrahim Mukhtar Saidu**

Cybersecurity Analyst & Security Researcher

**CYBERNOVA AI Cybersecurity Portfolio**

GitHub:

`https://github.com/ibrahim-mukhtar-saidu`

---

## 📜 License

This project is licensed under the MIT License.

See [LICENSE](LICENSE) for details.

---

## ⭐ Project Status

**Version:** `3.2`

**Status:** Hardened portfolio/laboratory release

### Current quality gates

```text
110 automated tests             PASS
99% code coverage               PASS
Ruff                            PASS
Ruff formatting                 PASS
Bandit                          0 findings
MyPy                            0 issues
pip-audit                       0 vulnerabilities
Python compilation              PASS
Git diff validation             PASS
Adversarial security testing    PASS
```

The project is intended to demonstrate practical defensive security engineering, secure Python development, Linux auditing, automated testing, and security validation.
