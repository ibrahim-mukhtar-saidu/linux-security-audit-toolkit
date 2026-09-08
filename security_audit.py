"""Linux security auditing and evidence collection toolkit.

This module performs read-only security checks against the local Linux host.
It is intended for authorized security auditing, training, and laboratory use.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess  # nosec B404
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "3.2"
AUTHOR = "Ibrahim Mukhtar Saidu"

PROJECT_ROOT = Path(__file__).resolve().parent
REPORT = PROJECT_ROOT / "reports" / "security_audit_report.txt"

COMMAND_TIMEOUT_SECONDS = 10
MAX_WORLD_WRITABLE_FILES = 10
MAX_SUID_FILES = 15

LOGGER = logging.getLogger(__name__)


PORT_INFO: dict[int, str] = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    631: "CUPS",
    5353: "mDNS",
    9050: "Tor SOCKS",
}

SERVICE_INFO: dict[str, str] = {
    "ssh": "SSH remote access service",
    "docker": "Docker container service",
    "bluetooth": "Bluetooth service",
    "cups": "Printing service",
    "avahi": "mDNS/DNS-SD service",
    "tor": "Tor anonymity service",
    "mysql": "MySQL database service",
}


@dataclass(frozen=True)
class CommandResult:
    """Result of a controlled external command."""

    command: tuple[str, ...]
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Return whether the command completed successfully."""
        return self.error is None and self.returncode == 0


@dataclass
class CollectionResult:
    """Collected evidence together with collection status."""

    values: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Return whether collection completed successfully."""
        return self.error is None


@dataclass(frozen=True)
class Finding:
    """A security observation and its risk context."""

    category: str
    severity: str
    title: str
    observation: str
    recommendation: str


@dataclass
class AuditData:
    """Normalized evidence collected from the host."""

    system_info: dict[str, str]
    users: list[str]
    services: CollectionResult
    ports: CollectionResult
    world_writable: CollectionResult
    suid_files: CollectionResult


@dataclass
class SecurityAnalysis:
    """Security analysis derived from collected evidence."""

    score: int
    risk_level: str
    findings: list[Finding]


def run_command(
    command: Sequence[str], timeout: int = COMMAND_TIMEOUT_SECONDS
) -> CommandResult:
    """Execute an external command without invoking a shell."""
    command_tuple = tuple(command)

    if not command_tuple:
        return CommandResult(
            command=command_tuple,
            error="Command cannot be empty.",
            returncode=None,
        )

    executable = shutil.which(command_tuple[0])
    if executable is None:
        return CommandResult(
            command=command_tuple,
            error=f"Command not found: {command_tuple[0]}",
            returncode=None,
        )

    try:
        completed = subprocess.run(  # nosec B603
            command_tuple,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=command_tuple,
            error=f"Command timed out after {timeout} seconds.",
            returncode=None,
        )
    except OSError as exc:
        return CommandResult(
            command=command_tuple,
            error=f"Unable to execute command: {exc}",
            returncode=None,
        )

    return CommandResult(
        command=command_tuple,
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )


def banner() -> None:
    """Display the toolkit banner."""
    print("=" * 50)
    print(" CyberNova Linux Security Audit Toolkit")
    print(f"              Version {VERSION}")
    print("=" * 50)


def get_system_info() -> dict[str, str]:
    """Collect basic host information."""
    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, OSError):
        current_user = "unknown"

    return {
        "OS": platform.system() or "unknown",
        "OS Release": platform.release() or "unknown",
        "Kernel": platform.version() or "unknown",
        "Hostname": socket.gethostname() or "unknown",
        "Current User": current_user,
    }


def get_users() -> list[str]:
    """Return local account names from the system password database."""
    try:
        return sorted({entry.pw_name for entry in pwd.getpwall() if entry.pw_name})
    except (OSError, KeyError):
        LOGGER.exception("Unable to enumerate local users.")
        return []


def get_services() -> CollectionResult:
    """Enumerate running systemd services."""
    result = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ]
    )

    if not result.ok:
        return CollectionResult(error=result.error or "systemctl failed.")

    services: list[str] = []

    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue

        service = fields[0]
        if service.endswith(".service"):
            services.append(service.removesuffix(".service"))

    return CollectionResult(values=sorted(set(services)))


_SS_PORT_PATTERN = re.compile(r"(?:^|:)(\d+)$")


def _extract_port(endpoint: str) -> int | None:
    """Extract a TCP/UDP port from an ss endpoint."""
    endpoint = endpoint.strip()

    if not endpoint or endpoint == "*":
        return None

    if endpoint.startswith("["):
        closing = endpoint.rfind("]")
        if closing == -1:
            return None
        suffix = endpoint[closing + 1 :]
        if not suffix.startswith(":"):
            return None
        port_text = suffix[1:]
    else:
        match = _SS_PORT_PATTERN.search(endpoint)
        if match is None:
            return None
        port_text = match.group(1)

    try:
        port = int(port_text)
    except ValueError:
        return None

    return port if 1 <= port <= 65535 else None


def _parse_ss_ports(output: str) -> list[int]:
    """Parse local listening ports from ``ss -tuln`` output."""
    ports: set[int] = set()

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped or stripped.lower().startswith("netid"):
            continue

        fields = stripped.split()

        # ``ss -tuln`` places the local endpoint immediately after the
        # connection-state field. This avoids accidentally treating a
        # numeric peer port as the listening port.
        if len(fields) < 5:
            continue

        local_endpoint = fields[4]
        port = _extract_port(local_endpoint)

        if port is not None:
            ports.add(port)

    return sorted(ports)


def get_ports() -> CollectionResult:
    """Collect listening TCP/UDP ports using ss."""
    result = run_command(["ss", "-tuln"])

    if not result.ok:
        return CollectionResult(error=result.error or "ss failed.")

    return CollectionResult(
        values=[str(port) for port in _parse_ss_ports(result.stdout)]
    )


def check_world_writable(
    directories: Sequence[Path] = (Path("/tmp"), Path("/var/tmp")),  # nosec B108
) -> CollectionResult:
    """Find regular world-writable files in selected temporary directories."""
    findings: list[str] = []

    for directory in directories:
        if not directory.exists():
            continue

        try:
            for root, dirnames, filenames in os.walk(directory):
                # Do not follow symbolic links through directory traversal.
                dirnames[:] = [
                    name
                    for name in dirnames
                    if not os.path.islink(os.path.join(root, name))
                ]

                for filename in filenames:
                    path = Path(root) / filename

                    try:
                        file_stat = path.stat()
                    except (FileNotFoundError, PermissionError, OSError):
                        continue

                    if not stat.S_ISREG(file_stat.st_mode):
                        continue

                    if file_stat.st_mode & stat.S_IWOTH:
                        findings.append(str(path))

                        if len(findings) >= MAX_WORLD_WRITABLE_FILES:
                            return CollectionResult(values=findings)

        except (PermissionError, OSError) as exc:
            return CollectionResult(
                values=findings,
                error=f"Unable to completely inspect {directory}: {exc}",
            )

    return CollectionResult(values=findings)


def check_suid_files(
    directories: Sequence[Path] = (Path("/usr/bin"), Path("/bin")),
) -> CollectionResult:
    """Find SUID regular files without invoking a shell."""
    existing_directories = [
        str(directory) for directory in directories if directory.is_dir()
    ]

    if not existing_directories:
        return CollectionResult(error="No configured SUID search directories exist.")

    command = [
        "find",
        *existing_directories,
        "-type",
        "f",
        "-perm",
        "-4000",
        "-print",
    ]

    result = run_command(command)

    if not result.ok:
        return CollectionResult(error=result.error or "find failed.")

    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]

    return CollectionResult(values=sorted(set(files))[:MAX_SUID_FILES])


def _known_port_description(port: int) -> str:
    """Return a known service description for a port."""
    return PORT_INFO.get(port, "Unknown or locally configured service")


def _service_description(service: str) -> str:
    """Return a known service description."""
    normalized = service.lower()
    return SERVICE_INFO.get(normalized, "Running system service")


def _risk_level(score: int) -> str:
    """Convert a numerical score into a risk classification."""
    if score >= 90:
        return "LOW RISK"
    if score >= 70:
        return "MODERATE RISK"
    if score >= 40:
        return "HIGH RISK"
    return "CRITICAL RISK"


def analyze_security(
    world_files: Sequence[str],
    suid_files: Sequence[str],
    ports: Sequence[int | str],
    *,
    collection_errors: Sequence[str] = (),
) -> SecurityAnalysis:
    """Analyze collected evidence using a deterministic scoring model."""
    score = 100
    findings: list[Finding] = []

    world_count = len(world_files)
    port_values: set[int] = set()

    for value in ports:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue

        if 1 <= port <= 65535:
            port_values.add(port)

    if world_count:
        score -= 20
        findings.append(
            Finding(
                category="Filesystem",
                severity="HIGH",
                title="World-writable files detected",
                observation=(
                    f"{world_count} world-writable regular file(s) were "
                    "identified in the audited temporary directories."
                ),
                recommendation=(
                    "Review ownership and permissions and remove world-write "
                    "access where it is not explicitly required."
                ),
            )
        )

    if len(port_values) > 5:
        score -= 10
        findings.append(
            Finding(
                category="Network",
                severity="MEDIUM",
                title="Multiple listening ports detected",
                observation=(
                    f"{len(port_values)} listening TCP/UDP port(s) were identified."
                ),
                recommendation=(
                    "Review each listening service and disable unnecessary "
                    "network exposure."
                ),
            )
        )
    elif port_values:
        findings.append(
            Finding(
                category="Network",
                severity="INFO",
                title="Listening ports detected",
                observation=(
                    f"{len(port_values)} listening port(s) were identified: "
                    + ", ".join(str(port) for port in sorted(port_values))
                ),
                recommendation=(
                    "Verify that each listening service is expected and "
                    "appropriately restricted."
                ),
            )
        )

    if suid_files:
        findings.append(
            Finding(
                category="Privilege",
                severity="INFO",
                title="SUID executables detected",
                observation=(
                    f"{len(suid_files)} SUID executable(s) were identified. "
                    "SUID is privileged functionality and is not inherently "
                    "a vulnerability."
                ),
                recommendation=(
                    "Review privileged executables for necessity, expected "
                    "ownership, permissions, provenance, and known security "
                    "issues."
                ),
            )
        )

    for error in collection_errors:
        findings.append(
            Finding(
                category="Collection",
                severity="MEDIUM",
                title="Audit collection incomplete",
                observation=error,
                recommendation=(
                    "Verify required system commands, permissions, and host "
                    "configuration before treating the audit as complete."
                ),
            )
        )
        score -= 5

    score = max(0, min(100, score))

    return SecurityAnalysis(
        score=score,
        risk_level=_risk_level(score),
        findings=findings,
    )


def collect_audit_data() -> AuditData:
    """Collect and normalize all audit evidence."""
    return AuditData(
        system_info=get_system_info(),
        users=get_users(),
        services=get_services(),
        ports=get_ports(),
        world_writable=check_world_writable(),
        suid_files=check_suid_files(),
    )


def _format_collection_section(
    title: str,
    result: CollectionResult,
    *,
    formatter: str = "list",
) -> list[str]:
    """Format a collection result for the text report."""
    lines = [title, "-" * len(title)]

    if result.error:
        lines.append(f"COLLECTION ERROR: {result.error}")

    if result.values:
        if formatter == "ports":
            for value in result.values:
                try:
                    port = int(value)
                except ValueError:
                    lines.append(value)
                    continue
                lines.append(f"{port} - {_known_port_description(port)}")
        elif formatter == "services":
            for value in result.values:
                lines.append(f"{value} - {_service_description(value)}")
        else:
            lines.extend(result.values)

    if not result.values and not result.error:
        lines.append("None identified.")

    lines.append("")
    return lines


def create_report(
    *,
    report_path: Path = REPORT,
    data: AuditData | None = None,
) -> str:
    """Generate and write the human-readable audit report."""
    audit_data = data or collect_audit_data()

    port_values = audit_data.ports.values
    collection_errors = [
        f"{name}: {error}"
        for name, error in (
            ("Running services", audit_data.services.error),
            ("Listening ports", audit_data.ports.error),
            ("World-writable files", audit_data.world_writable.error),
            ("SUID files", audit_data.suid_files.error),
        )
        if error
    ]

    analysis = analyze_security(
        audit_data.world_writable.values,
        audit_data.suid_files.values,
        port_values,
        collection_errors=collection_errors,
    )

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    lines = [
        "=" * 60,
        "CYBERNOVA LINUX SECURITY AUDIT TOOLKIT",
        "=" * 60,
        f"Version: {VERSION}",
        f"Author: {AUTHOR}",
        f"Audit Timestamp (UTC): {timestamp}",
        "",
        "SYSTEM INFORMATION",
        "------------------",
    ]

    lines.extend(f"{key}: {value}" for key, value in audit_data.system_info.items())
    lines.append("")

    lines.extend(
        _format_collection_section(
            "RUNNING SERVICES",
            audit_data.services,
            formatter="services",
        )
    )

    lines.extend(
        _format_collection_section(
            "LISTENING PORTS",
            audit_data.ports,
            formatter="ports",
        )
    )

    lines.extend(
        _format_collection_section(
            "WORLD-WRITABLE FILES",
            audit_data.world_writable,
        )
    )

    lines.extend(
        _format_collection_section(
            "SUID FILES",
            audit_data.suid_files,
        )
    )

    lines.extend(
        [
            "SECURITY ANALYSIS",
            "------------------",
            f"Security Score: {analysis.score}/100",
            f"Risk Level: {analysis.risk_level}",
            f"Findings: {len(analysis.findings)}",
            "",
        ]
    )

    if analysis.findings:
        for index, finding in enumerate(analysis.findings, start=1):
            lines.extend(
                [
                    f"[{index}] {finding.title}",
                    f"Category: {finding.category}",
                    f"Severity: {finding.severity}",
                    f"Observation: {finding.observation}",
                    f"Recommendation: {finding.recommendation}",
                    "",
                ]
            )
    else:
        lines.extend(
            [
                "No security findings identified by the configured checks.",
                "",
            ]
        )

    lines.extend(
        [
            "LABORATORY SCOPE",
            "----------------",
            "This report represents read-only local host observations.",
            "Results require contextual review by an authorized operator.",
            "The toolkit does not perform automatic remediation.",
            "",
            "=" * 60,
            "END OF REPORT",
            "=" * 60,
        ]
    )

    report = "\n".join(lines) + "\n"

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")

    return report


def main() -> None:
    """Run the default audit and print the generated report."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    print(create_report())


if __name__ == "__main__":
    main()
