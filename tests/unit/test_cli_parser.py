from safedeps.cli_parser import build_parser


def _handler(_args):
    return 0


def _parser():
    return build_parser(
        version="0.0.0-test",
        severity_choices={"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
        handlers={
            "version": _handler,
            "help": _handler,
            "init": _handler,
            "scan": _handler,
            "doctor": _handler,
            "explain": _handler,
            "baseline": _handler,
            "approve": _handler,
            "ui": _handler,
            "ui-shortcut": _handler,
            "setup": _handler,
            "guard-cleanup": _handler,
        },
    )


def test_cli_parser_scan_defaults_and_report_options():
    args = _parser().parse_args(
        [
            "scan",
            "project",
            "--fail-on",
            "CRITICAL",
            "--sarif",
            "reports/safedeps.sarif",
            "--online-audit",
        ]
    )

    assert args.path == "project"
    assert args.fail_on == "CRITICAL"
    assert args.sarif == "reports/safedeps.sarif"
    assert args.online_audit is True
    assert args.func is _handler


def test_cli_parser_setup_scope_options():
    args = _parser().parse_args(
        [
            "setup",
            ".",
            "--install-scope",
            "system",
            "--protection-scope",
            "global",
            "--force",
        ]
    )

    assert args.path == "."
    assert args.install_scope == "system"
    assert args.protection_scope == "global"
    assert args.force is True


def test_cli_parser_approve_required_fields():
    args = _parser().parse_args(
        [
            "approve",
            ".",
            "--manager",
            "pip",
            "--rule",
            "UNPINNED_VERSION",
            "--expires",
            "2026-12-31",
        ]
    )

    assert args.manager == "pip"
    assert args.rule == "UNPINNED_VERSION"
    assert args.expires == "2026-12-31"
    assert args.package == ""
