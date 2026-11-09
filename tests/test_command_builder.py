import pytest

from nmap_gui.core.command_builder import (
    PROFILES,
    ScanOptions,
    ValidationError,
    apply_profile,
    build_args,
    display_command,
    needs_privileges,
)


def test_basic_target():
    assert build_args(ScanOptions(targets="192.168.1.1")) == ["192.168.1.1"]


def test_multiple_targets_and_options():
    opts = ScanOptions(
        targets="10.0.0.0/24, ejemplo.com", scan_type="-sT", ports="22, 80", service_version=True, timing=4
    )
    assert build_args(opts) == ["-sT", "-p", "22,80", "-sV", "-T4", "10.0.0.0/24", "ejemplo.com"]


def test_aggressive_replaces_individual_flags():
    args = build_args(ScanOptions(targets="h", aggressive=True, service_version=True, os_detection=True))
    assert "-A" in args and "-sV" not in args and "-O" not in args


def test_ping_scan_ignores_ports():
    args = build_args(ScanOptions(targets="h", scan_type="-sn", ports="80", fast=True, service_version=True))
    assert args == ["-sn", "h"]


@pytest.mark.parametrize("target", ["-oN", "-iL/etc/passwd", "a;rm", "$(id)", "a|b", "`x`"])
def test_rejects_dangerous_targets(target):
    with pytest.raises(ValidationError):
        build_args(ScanOptions(targets=target))


def test_empty_target():
    with pytest.raises(ValidationError):
        build_args(ScanOptions(targets="   "))


@pytest.mark.parametrize("extra", ["-oN out.txt", "-oX x.xml", "--resume f", "'unclosed"])
def test_rejects_forbidden_extra_args(extra):
    with pytest.raises(ValidationError):
        build_args(ScanOptions(targets="h", extra_args=extra))


def test_extra_args_allowed():
    assert build_args(ScanOptions(targets="h", extra_args="--max-retries 2")) == ["--max-retries", "2", "h"]


def test_bad_ports_and_scripts():
    with pytest.raises(ValidationError):
        build_args(ScanOptions(targets="h", ports="80;ls"))
    with pytest.raises(ValidationError):
        build_args(ScanOptions(targets="h", scripts="vuln;x"))


def test_scripts():
    assert build_args(ScanOptions(targets="h", scripts="http-title, ssl-cert")) == [
        "--script=http-title,ssl-cert",
        "h",
    ]


def test_all_profiles_build():
    for name in PROFILES:
        assert build_args(apply_profile(name, "127.0.0.1"))[-1] == "127.0.0.1"


def test_profile_copy_is_independent():
    p = apply_profile("Escaneo rápido", "x")
    p.fast = False
    assert PROFILES["Escaneo rápido"].fast is True


def test_display_and_privileges():
    args = build_args(ScanOptions(targets="h", scan_type="-sS"))
    assert display_command(args) == "nmap -sS h"
    assert needs_privileges(args)
    assert not needs_privileges(["-sT", "h"])
