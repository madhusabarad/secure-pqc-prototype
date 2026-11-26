"""CLI wrapper around app.audit.verify_audit_log with optional anchor verification.

Exit code:
  0: Audit log and checkpoint completely verified.
  1: Verification failure (tampering, gap, truncation, or signature failure).
"""

import argparse
from pathlib import Path
import sys
import tempfile

# Add parent directory to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))
from app import audit
from app.store import get_state_dir


def main():
    parser = argparse.ArgumentParser(description="Verify tamper-evident audit log integrity.")
    parser.add_argument(
        "--state-dir",
        default=None,
        help="Path to state directory containing audit.log and checkpoint.json (default: TRACK4_STATE_DIR or system temp)",
    )
    parser.add_argument(
        "--anchor",
        default=None,
        help="Optional external anchor head hash to verify in the log chain",
    )
    args = parser.parse_args()

    state_dir = Path(args.state_dir).resolve() if args.state_dir else get_state_dir()
    print(f"Verifying audit log in: {state_dir}")
    if args.anchor:
        print(f"Verifying external anchor head: {args.anchor}")

    report = audit.verify_audit_log(state_dir, anchor_head=args.anchor)

    if report["valid"]:
        print(f"VERIFICATION SUCCESSFUL: {report['entries_count']} entries verified.")
        print(f"Current Log Head: {report['head']}")
        return 0
    else:
        print("VERIFICATION FAILED:")
        if report.get("bad_line") is not None:
            print(f"  First invalid line : {report['bad_line']}")
        print(f"  Reason             : {report.get('reason')}")
        print(f"  Valid entries prior: {report.get('entries_count')}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
