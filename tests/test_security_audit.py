from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

import security_audit

# ---------------------------------------------------------------------------
# Metadata / public API
# ---------------------------------------------------------------------------


def test_project_metadata() -> None:
    assert security_audit.VERSION == "3.2"
    assert security_audit.AUTHOR == "Ibrahim Mukhtar Saidu"
    assert security_audit.REPORT.name == "security_audit_report.txt"


@pytest.mark.parametrize(
    "name",
    [
        "banner",
        "get_system_info",
        "get_users",
        "get_services",
        "get_ports",
        "check_world_writable",
        "check_suid_files",
        "analyze_security",
        "create_report",
        "main",
    ],
)
def test_public_api_symbols_exist(name: str) -> None:
    assert hasattr(security_audit, name)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


def test_command_result_success() -> None:
    result = security_audit.CommandResult(
        command=("echo", "hello"),
        stdout="hello\n",
        returncode=0,
    )

    assert result.ok is True
    assert result.error is None
    assert result.stdout == "hello\n"
    assert result.returncode == 0


def test_command_result_failure() -> None:
    result = security_audit.CommandResult(
        command=("false",),
        stderr="failure\n",
        returncode=1,
    )

    assert result.ok is False
    assert result.returncode == 1


def test_command_result_error() -> None:
    result = security_audit.CommandResult(
        command=("missing",),
        returncode=None,
        error="Command not found: missing",
    )

    assert result.ok is False
    assert result.error == "Command not found: missing"


def test_collection_result_success() -> None:
    result = security_audit.CollectionResult(
        values=["one", "two"],
    )

    assert result.ok is True
    assert result.values == ["one", "two"]
    assert result.error is None


def test_collection_result_failure() -> None:
    result = security_audit.CollectionResult(
        error="collection failed",
    )

    assert result.ok is False
    assert result.values == []
    assert result.error == "collection failed"


# ---------------------------------------------------------------------------
# Controlled command execution
# ---------------------------------------------------------------------------


def test_run_command_success() -> None:
    with (
        patch(
            "security_audit.shutil.which",
            return_value="/usr/bin/printf",
        ),
        patch("security_audit.subprocess.run") as mocked_run,
    ):
        mocked_run.return_value = subprocess.CompletedProcess(
            args=["printf", "hello"],
            returncode=0,
            stdout="hello",
            stderr="",
        )

        result = security_audit.run_command(["printf", "hello"])

    assert result.ok is True
    assert result.stdout == "hello"
    assert result.stderr == ""
    assert result.returncode == 0

    mocked_run.assert_called_once()


def test_run_command_missing_command() -> None:
    with patch("security_audit.shutil.which", return_value=None):
        result = security_audit.run_command(["does-not-exist"])

    assert result.ok is False
    assert result.returncode is None
    assert result.error == "Command not found: does-not-exist"


def test_run_command_timeout() -> None:
    timeout = subprocess.TimeoutExpired(
        cmd=["ss", "-tuln"],
        timeout=10,
    )

    with (
        patch(
            "security_audit.shutil.which",
            return_value="/usr/bin/ss",
        ),
        patch(
            "security_audit.subprocess.run",
            side_effect=timeout,
        ),
    ):
        result = security_audit.run_command(["ss", "-tuln"])

    assert result.ok is False
    assert result.returncode is None
    assert result.error == "Command timed out after 10 seconds."


def test_run_command_permission_error() -> None:
    with (
        patch(
            "security_audit.shutil.which",
            return_value="/usr/bin/ss",
        ),
        patch(
            "security_audit.subprocess.run",
            side_effect=PermissionError("permission denied"),
        ),
    ):
        result = security_audit.run_command(["ss", "-tuln"])

    assert result.ok is False
    assert result.returncode is None
    assert result.error == "Unable to execute command: permission denied"


def test_run_command_nonzero_exit() -> None:
    with (
        patch(
            "security_audit.shutil.which",
            return_value="/usr/bin/test-command",
        ),
        patch("security_audit.subprocess.run") as mocked_run,
    ):
        mocked_run.return_value = subprocess.CompletedProcess(
            args=["test-command"],
            returncode=2,
            stdout="",
            stderr="bad input",
        )

        result = security_audit.run_command(["test-command"])

    assert result.ok is False
    assert result.returncode == 2
    assert result.stderr == "bad input"
    assert result.error is None


# ---------------------------------------------------------------------------
# System information / users
# ---------------------------------------------------------------------------


def test_get_system_info_contains_expected_keys() -> None:
    info = security_audit.get_system_info()

    assert set(info) == {
        "OS",
        "OS Release",
        "Kernel",
        "Hostname",
        "Current User",
    }


def test_get_system_info_uses_real_uid_identity() -> None:
    info = security_audit.get_system_info()

    assert info["Current User"]
    assert info["Current User"] != "None"


def test_get_users_returns_list() -> None:
    users = security_audit.get_users()

    assert isinstance(users, list)
    assert all(isinstance(user, str) for user in users)


def test_get_users_handles_pwd_failure() -> None:
    with patch(
        "security_audit.pwd.getpwall",
        side_effect=OSError("permission denied"),
    ):
        users = security_audit.get_users()

    assert users == []


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def test_get_services_success() -> None:
    output = (
        "ssh.service loaded active running OpenSSH server\n"
        "docker.service loaded active running Docker\n"
    )

    result = security_audit.CommandResult(
        command=("systemctl",),
        stdout=output,
        returncode=0,
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ):
        services = security_audit.get_services()

    assert services.ok is True
    assert services.values == ["docker", "ssh"]


def test_get_services_command_failure() -> None:
    result = security_audit.CommandResult(
        command=("systemctl",),
        returncode=None,
        error="command unavailable",
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ):
        services = security_audit.get_services()

    assert services.ok is False
    assert services.values == []
    assert services.error == "command unavailable"


def test_get_services_ignores_non_service_lines() -> None:
    output = "header text\nnot-a-service\nssh.service loaded active running OpenSSH\n"

    result = security_audit.CommandResult(
        command=("systemctl",),
        stdout=output,
        returncode=0,
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ):
        services = security_audit.get_services()

    assert services.values == ["ssh"]


# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("", None),
        ("abc", None),
        ("0", None),
        ("-1", None),
        ("65535", 65535),
        ("65536", None),
        ("8080", 8080),
        ("127.0.0.1:443", 443),
        ("0.0.0.0:22", 22),
        ("[::1]:8443", 8443),
        ("[::]:443", 443),
    ],
)
def test_extract_port(token: str, expected: int | None) -> None:
    assert security_audit._extract_port(token) == expected


def test_parse_ss_ports_empty() -> None:
    assert security_audit._parse_ss_ports("") == []


def test_parse_ss_ports_header() -> None:
    sample = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port"

    assert security_audit._parse_ss_ports(sample) == []


def test_parse_ss_ports_ipv4() -> None:
    sample = "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*"

    assert security_audit._parse_ss_ports(sample) == [8080]


def test_parse_ss_ports_ipv6() -> None:
    sample = "tcp LISTEN 0 128 [::1]:8443 [::]:*"

    assert security_audit._parse_ss_ports(sample) == [8443]


def test_parse_ss_ports_wildcard() -> None:
    sample = "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*"

    assert security_audit._parse_ss_ports(sample) == [443]


def test_parse_ss_ports_multiple_ports_sorted_unique() -> None:
    sample = """tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*
tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*
tcp LISTEN 0 128 127.0.0.1:443 0.0.0.0:*
tcp LISTEN 0 128 [::1]:8080 [::]:*"""

    assert security_audit._parse_ss_ports(sample) == [22, 443, 8080]


def test_parse_ss_ports_malformed() -> None:
    sample = "tcp LISTEN invalid-data not-a-port"

    assert security_audit._parse_ss_ports(sample) == []


def test_get_ports_success() -> None:
    result = security_audit.CommandResult(
        command=("ss", "-tuln"),
        stdout=(
            "tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:443 0.0.0.0:*\n"
        ),
        returncode=0,
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ):
        ports = security_audit.get_ports()

    assert ports.ok is True
    assert ports.values == ["22", "443"]


def test_get_ports_failure() -> None:
    result = security_audit.CommandResult(
        command=("ss", "-tuln"),
        returncode=None,
        error="permission denied",
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ):
        ports = security_audit.get_ports()

    assert ports.ok is False
    assert ports.values == []
    assert ports.error == "permission denied"


# ---------------------------------------------------------------------------
# World-writable file detection
# ---------------------------------------------------------------------------


def test_check_world_writable_missing_directory() -> None:
    with patch(
        "security_audit.Path.exists",
        return_value=False,
    ):
        result = security_audit.check_world_writable()

    assert result.ok is True
    assert result.values == []


def test_check_world_writable_detects_world_writable_file(
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "world-writable.txt"
    test_file.write_text("test", encoding="utf-8")
    test_file.chmod(0o666)

    result = security_audit.check_world_writable(
        directories=[tmp_path],
    )

    assert result.ok is True
    assert str(test_file) in result.values


def test_check_world_writable_ignores_normal_file(
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "normal.txt"
    test_file.write_text("test", encoding="utf-8")
    test_file.chmod(0o644)

    result = security_audit.check_world_writable(
        directories=[tmp_path],
    )

    assert result.ok is True
    assert result.values == []


# ---------------------------------------------------------------------------
# SUID detection
# ---------------------------------------------------------------------------


def test_check_suid_files_success() -> None:
    result = security_audit.CommandResult(
        command=("find",),
        stdout="/usr/bin/sudo\n/usr/bin/passwd\n",
        returncode=0,
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ):
        suid = security_audit.check_suid_files()

    assert suid.ok is True
    assert suid.values == [
        "/usr/bin/passwd",
        "/usr/bin/sudo",
    ]


def test_check_suid_files_failure() -> None:
    result = security_audit.CommandResult(
        command=("find",),
        returncode=None,
        error="command unavailable",
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ):
        suid = security_audit.check_suid_files()

    assert suid.ok is False
    assert suid.values == []
    assert suid.error == "command unavailable"


# ---------------------------------------------------------------------------
# Security scoring
# ---------------------------------------------------------------------------


def test_clean_system_scores_100() -> None:
    analysis = security_audit.analyze_security(
        [],
        [],
        [],
    )

    assert analysis.score == 100
    assert analysis.risk_level == "LOW RISK"
    assert analysis.findings == []


def test_one_to_five_ports_do_not_reduce_score() -> None:
    analysis = security_audit.analyze_security(
        [],
        [],
        [22, 53, 80, 443, 631],
    )

    assert analysis.score == 100
    assert len(analysis.findings) == 1


def test_six_ports_reduce_score() -> None:
    analysis = security_audit.analyze_security(
        [],
        [],
        [1, 2, 3, 4, 5, 6],
    )

    assert analysis.score == 90
    assert analysis.risk_level == "LOW RISK"


def test_world_writable_files_reduce_score() -> None:
    analysis = security_audit.analyze_security(
        ["/tmp/test.txt"],
        [],
        [],
    )

    assert analysis.score == 80
    assert analysis.risk_level == "MODERATE RISK"


def test_suid_is_informational() -> None:
    analysis = security_audit.analyze_security(
        [],
        ["/usr/bin/sudo"],
        [],
    )

    assert analysis.score == 100
    assert analysis.risk_level == "LOW RISK"
    assert len(analysis.findings) == 1
    assert analysis.findings[0].severity == "INFO"


def test_multiple_risks_reduce_score() -> None:
    analysis = security_audit.analyze_security(
        ["/tmp/test.txt"],
        ["/usr/bin/sudo"],
        [1, 2, 3, 4, 5, 6],
    )

    assert analysis.score == 70
    assert analysis.risk_level == "MODERATE RISK"
    assert len(analysis.findings) == 3


def test_collection_error_reduces_confidence_score() -> None:
    analysis = security_audit.analyze_security(
        [],
        [],
        [],
        collection_errors=["ss: command unavailable"],
    )

    assert analysis.score == 95
    assert analysis.risk_level == "LOW RISK"
    assert len(analysis.findings) == 1


@pytest.mark.parametrize(
    ("world", "ports", "expected_score"),
    [
        ([], [], 100),
        ([], [1, 2, 3, 4, 5], 100),
        ([], [1, 2, 3, 4, 5, 6], 90),
        (["a"], [], 80),
        (["a"], [1, 2, 3, 4, 5, 6], 70),
    ],
)
def test_score_boundaries(
    world: list[str],
    ports: list[int],
    expected_score: int,
) -> None:
    analysis = security_audit.analyze_security(
        world,
        [],
        ports,
    )

    assert 0 <= analysis.score <= 100
    assert analysis.score == expected_score


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def test_create_report_uses_custom_path(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.txt"

    report = security_audit.create_report(
        report_path=report_path,
    )

    assert report_path.exists()
    assert report_path.read_text(encoding="utf-8") == report


def test_report_contains_required_sections(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.txt"

    report = security_audit.create_report(
        report_path=report_path,
    )

    required_sections = [
        "SYSTEM INFORMATION",
        "RUNNING SERVICES",
        "LISTENING PORTS",
        "WORLD-WRITABLE FILES",
        "SUID FILES",
        "Security Score:",
        "Risk Level:",
        "Findings:",
        "LABORATORY SCOPE",
        "END OF REPORT",
    ]

    for section in required_sections:
        assert section in report


def test_report_uses_utc_timestamp(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.txt"

    report = security_audit.create_report(
        report_path=report_path,
    )

    assert "Audit Timestamp (UTC):" in report
    timestamp_line = next(
        line
        for line in report.splitlines()
        if line.startswith("Audit Timestamp (UTC):")
    )

    timestamp = timestamp_line.split(":", 1)[1].strip()

    assert timestamp.endswith("+00:00")


def test_report_writes_utf8(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.txt"

    security_audit.create_report(
        report_path=report_path,
    )

    raw = report_path.read_bytes()

    assert raw.decode("utf-8")


def test_report_path_is_project_relative_by_default() -> None:
    expected = (
        Path(security_audit.PROJECT_ROOT) / "reports" / "security_audit_report.txt"
    )

    assert security_audit.REPORT == expected


# ---------------------------------------------------------------------------
# Security regression checks
# ---------------------------------------------------------------------------


def test_no_shell_execution_in_source() -> None:
    source = Path("security_audit.py").read_text(
        encoding="utf-8",
    )

    assert "shell=True" not in source


def test_no_bare_except_in_source() -> None:
    source = Path("security_audit.py").read_text(
        encoding="utf-8",
    )

    assert "except:" not in source


def test_no_environment_user_identity_lookup() -> None:
    source = Path("security_audit.py").read_text(
        encoding="utf-8",
    )

    assert "os.getenv('USER')" not in source
    assert 'os.getenv("USER")' not in source


def test_no_naive_datetime_now() -> None:
    source = Path("security_audit.py").read_text(
        encoding="utf-8",
    )

    assert "datetime.datetime.now()" not in source


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_banner(capsys: pytest.CaptureFixture[str]) -> None:
    security_audit.banner()

    output = capsys.readouterr().out

    assert "CyberNova Linux Security Audit Toolkit" in output
    assert "Version 3.2" in output


def test_main_version(capsys: pytest.CaptureFixture[str]) -> None:
    with patch(
        "security_audit.create_report",
        return_value="",
    ):
        # main() has no CLI argument handling; this validates the callable.
        result = security_audit.main()

    assert result is None


# ---------------------------------------------------------------------------
# Environment safety
# ---------------------------------------------------------------------------


def test_project_root_is_absolute() -> None:
    assert security_audit.PROJECT_ROOT.is_absolute()


def test_report_parent_directory_exists() -> None:
    assert security_audit.REPORT.parent.exists()


# ---------------------------------------------------------------------------
# Additional defensive / branch coverage
# ---------------------------------------------------------------------------


def test_run_command_rejects_empty_command() -> None:
    result = security_audit.run_command([])

    assert result.ok is False
    assert result.returncode is None
    assert result.error == "Command cannot be empty."


def test_get_system_info_handles_unknown_uid() -> None:
    with patch(
        "security_audit.pwd.getpwuid",
        side_effect=KeyError(99999),
    ):
        info = security_audit.get_system_info()

    assert info["Current User"] == "unknown"


def test_get_system_info_handles_os_error() -> None:
    with patch(
        "security_audit.pwd.getpwuid",
        side_effect=OSError("uid lookup failed"),
    ):
        info = security_audit.get_system_info()

    assert info["Current User"] == "unknown"


def test_get_system_info_uses_unknown_platform_values() -> None:
    with (
        patch("security_audit.platform.system", return_value=""),
        patch("security_audit.platform.release", return_value=""),
        patch("security_audit.platform.version", return_value=""),
    ):
        info = security_audit.get_system_info()

    assert info["OS"] == "unknown"
    assert info["OS Release"] == "unknown"
    assert info["Kernel"] == "unknown"


def test_extract_port_rejects_invalid_ipv6_endpoint() -> None:
    assert security_audit._extract_port("[::1]") is None


def test_extract_port_rejects_ipv6_without_port() -> None:
    assert security_audit._extract_port("[::1]:") is None


def test_extract_port_rejects_malformed_ipv6() -> None:
    assert security_audit._extract_port("[::1:8443") is None


def test_parse_ss_ports_skips_invalid_port_values() -> None:
    sample = """tcp LISTEN abc 0 127.0.0.1:abc 0.0.0.0:*
tcp LISTEN xyz 0 127.0.0.1:0 0.0.0.0:*
tcp LISTEN xyz 0 127.0.0.1:65536 0.0.0.0:*
tcp LISTEN xyz 0 127.0.0.1:443 0.0.0.0:*"""

    assert security_audit._parse_ss_ports(sample) == [443]


def test_world_writable_limit_is_enforced(tmp_path: Path) -> None:
    files = []

    for index in range(security_audit.MAX_WORLD_WRITABLE_FILES + 5):
        path = tmp_path / f"world-{index}.txt"
        path.write_text("test", encoding="utf-8")
        path.chmod(0o666)
        files.append(path)

    result = security_audit.check_world_writable(
        directories=[tmp_path],
    )

    assert result.ok is True
    assert len(result.values) == security_audit.MAX_WORLD_WRITABLE_FILES


def test_world_writable_ignores_directory_symlinks(
    tmp_path: Path,
) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()

    dangerous_file = real_directory / "dangerous.txt"
    dangerous_file.write_text("test", encoding="utf-8")
    dangerous_file.chmod(0o666)

    link = tmp_path / "linked-directory"

    try:
        link.symlink_to(real_directory, target_is_directory=True)
    except OSError:
        pytest.skip("Filesystem does not support directory symlinks.")

    result = security_audit.check_world_writable(
        directories=[tmp_path],
    )

    assert result.ok is True
    assert str(dangerous_file) in result.values


def test_world_writable_handles_stat_race(
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "race.txt"
    test_file.write_text("test", encoding="utf-8")

    original_stat = Path.stat

    def failing_stat(self: Path, *args: object, **kwargs: object):
        if self == test_file:
            raise FileNotFoundError("file disappeared")
        return original_stat(self, *args, **kwargs)

    with patch.object(Path, "stat", failing_stat):
        result = security_audit.check_world_writable(
            directories=[tmp_path],
        )

    assert result.ok is True
    assert result.values == []


def test_world_writable_handles_directory_permission_error(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "restricted"
    directory.mkdir()

    def failing_walk(*args: object, **kwargs: object):
        raise PermissionError("permission denied")

    with patch(
        "security_audit.os.walk",
        side_effect=failing_walk,
    ):
        result = security_audit.check_world_writable(
            directories=[directory],
        )

    assert result.ok is False
    assert result.values == []
    assert "Unable to completely inspect" in (result.error or "")


def test_suid_handles_missing_directories(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does-not-exist"

    result = security_audit.check_suid_files(
        directories=[missing],
    )

    assert result.ok is False
    assert result.values == []
    assert result.error == "No configured SUID search directories exist."


def test_suid_accepts_existing_directory_and_builds_find_command(
    tmp_path: Path,
) -> None:
    result = security_audit.CommandResult(
        command=("find",),
        stdout="/usr/bin/passwd\n",
        returncode=0,
    )

    with patch(
        "security_audit.run_command",
        return_value=result,
    ) as mocked_run:
        suid = security_audit.check_suid_files(
            directories=[tmp_path],
        )

    assert suid.ok is True
    assert suid.values == ["/usr/bin/passwd"]

    command = mocked_run.call_args.args[0]

    assert command[0] == "find"
    assert str(tmp_path) in command
    assert "-type" in command
    assert "f" in command
    assert "-perm" in command
    assert "-4000" in command
    assert "-print" in command


def test_suid_results_are_limited(tmp_path: Path) -> None:
    output = "\n".join(
        f"/usr/bin/test-{i}" for i in range(security_audit.MAX_SUID_FILES + 5)
    )

    result = security_audit.CommandResult(
        command=("find",),
        stdout=output,
        returncode=0,
    )

    existing_directory = tmp_path

    with (
        patch.object(
            Path,
            "is_dir",
            return_value=True,
        ),
        patch(
            "security_audit.run_command",
            return_value=result,
        ),
    ):
        suid = security_audit.check_suid_files(
            directories=[existing_directory],
        )

    assert suid.ok is True
    assert len(suid.values) == security_audit.MAX_SUID_FILES


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100, "LOW RISK"),
        (90, "LOW RISK"),
        (89, "MODERATE RISK"),
        (70, "MODERATE RISK"),
        (69, "HIGH RISK"),
        (40, "HIGH RISK"),
        (39, "CRITICAL RISK"),
        (0, "CRITICAL RISK"),
    ],
)
def test_risk_level_boundaries(
    score: int,
    expected: str,
) -> None:
    assert security_audit._risk_level(score) == expected


def test_analyze_security_ignores_invalid_port_values() -> None:
    analysis = security_audit.analyze_security(
        [],
        [],
        ["abc", "", None, 0, -1, 65536, 443],
    )

    assert analysis.score == 100
    assert len(analysis.findings) == 1
    assert analysis.findings[0].category == "Network"


def test_analyze_security_deduplicates_ports() -> None:
    analysis = security_audit.analyze_security(
        [],
        [],
        [443, "443", 443, 80],
    )

    assert analysis.score == 100
    assert len(analysis.findings) == 1


def test_format_empty_collection() -> None:
    result = security_audit.CollectionResult()

    lines = security_audit._format_collection_section(
        "TEST SECTION",
        result,
    )

    assert "None identified." in lines


def test_format_collection_error() -> None:
    result = security_audit.CollectionResult(
        error="command unavailable",
    )

    lines = security_audit._format_collection_section(
        "TEST SECTION",
        result,
    )

    assert "COLLECTION ERROR: command unavailable" in lines


def test_format_ports_with_invalid_value() -> None:
    result = security_audit.CollectionResult(
        values=["443", "not-a-port"],
    )

    lines = security_audit._format_collection_section(
        "PORTS",
        result,
        formatter="ports",
    )

    assert "443 - HTTPS" in lines
    assert "not-a-port" in lines


def test_format_services_uses_known_description() -> None:
    result = security_audit.CollectionResult(
        values=["ssh"],
    )

    lines = security_audit._format_collection_section(
        "SERVICES",
        result,
        formatter="services",
    )

    assert any("ssh -" in line for line in lines)


def test_format_unknown_service_uses_default_description() -> None:
    result = security_audit.CollectionResult(
        values=["custom-service"],
    )

    lines = security_audit._format_collection_section(
        "SERVICES",
        result,
        formatter="services",
    )

    assert "custom-service - Running system service" in lines


def test_create_report_with_supplied_audit_data(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "nested" / "audit.txt"

    audit_data = security_audit.AuditData(
        system_info={
            "OS": "TestOS",
            "OS Release": "1.0",
            "Kernel": "test-kernel",
            "Hostname": "test-host",
            "Current User": "test-user",
        },
        users=["alice", "bob"],
        services=security_audit.CollectionResult(
            values=["ssh"],
        ),
        ports=security_audit.CollectionResult(
            values=["443"],
        ),
        world_writable=security_audit.CollectionResult(),
        suid_files=security_audit.CollectionResult(),
    )

    report = security_audit.create_report(
        report_path=report_path,
        data=audit_data,
    )

    assert report_path.exists()
    assert "TestOS" in report
    assert "test-host" in report
    assert "test-user" in report
    assert "443 - HTTPS" in report


def test_main_prints_generated_report(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch(
        "security_audit.create_report",
        return_value="TEST REPORT",
    ):
        result = security_audit.main()

    captured = capsys.readouterr()

    assert result is None
    assert "TEST REPORT" in captured.out
