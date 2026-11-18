"""ScrubZero CLI: scrubzero [FILE|-] [--entities ...] [--replacement label|hash] [--report PATH]"""

from __future__ import annotations

import argparse
import json
import sys

from .core import scrub
from .recognizers import ENTITIES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scrubzero",
        description="Strip PII and secrets from text — zero dependencies, checksum-validated.",
    )
    parser.add_argument("file", nargs="?", default="-", help="input file, or - / omitted for stdin")
    parser.add_argument(
        "--entities",
        default=None,
        help=f"comma-separated subset of: {','.join(ENTITIES)}",
    )
    parser.add_argument("--replacement", choices=["label", "hash"], default="label")
    parser.add_argument("--report", default=None, help="write the JSON redaction report here")
    args = parser.parse_args(argv)

    try:
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8") as fh:
                text = fh.read()
    except OSError as exc:
        print(f"scrubzero: cannot read input: {exc}", file=sys.stderr)
        return 2

    entities = (
        tuple(e.strip().upper() for e in args.entities.split(",") if e.strip())
        if args.entities
        else None
    )
    try:
        clean, report = scrub(text, entities=entities, replacement=args.replacement)
    except ValueError as exc:
        print(f"scrubzero: {exc}", file=sys.stderr)
        return 2

    sys.stdout.write(clean)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2)
    else:
        print(
            f"scrubzero: {report.total} redaction(s) {report.counts}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
