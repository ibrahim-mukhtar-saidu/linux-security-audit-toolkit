#!/usr/bin/env python3

import argparse
import security_audit


def main():
    parser = argparse.ArgumentParser(
        description="CyberNova Linux Security Audit Toolkit"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"CyberNova Linux Security Audit Toolkit v{security_audit.VERSION}"
    )

    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run a complete Linux security audit"
    )

    args = parser.parse_args()

    if args.audit:
        security_audit.banner()
        security_audit.create_report()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
