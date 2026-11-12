import argparse
import sys
from pathlib import Path

import yaml

from . import backends, lint, match
from .sigma import SigmaError, load_dir

ROOT = Path(__file__).resolve().parent.parent


def cmd_lint(rules):
    failed = 0
    for msg in lint.duplicate_ids(rules):
        print(f"FAIL  {msg}")
        failed += 1
    for r in rules:
        for p in lint.lint(r):
            print(f"FAIL  {r.name}: {p}")
            failed += 1
    print(f"{len(rules)} rules linted, {failed} problem(s)")
    return 1 if failed else 0


def cmd_test(rules, events_dir):
    failed = 0
    for r in rules:
        f = events_dir / f"{r.name}.yml"
        if not f.exists():
            print(f"FAIL  {r.name}: no test events ({f.relative_to(ROOT)})")
            failed += 1
            continue
        cases = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        if not cases.get("match"):
            print(f"FAIL  {r.name}: needs at least one 'match' event")
            failed += 1
        for expected, key in ((True, "match"), (False, "no_match")):
            for i, ev in enumerate(cases.get(key, [])):
                if match.matches(r, ev) != expected:
                    print(f"FAIL  {r.name}: {key}[{i}] {'did not match' if expected else 'matched'}")
                    failed += 1
        if not failed:
            print(f"ok    {r.name}")
    print(f"{len(rules)} rules tested, {failed} failure(s)")
    return 1 if failed else 0


def cmd_convert(rules, target, out_dir):
    be = backends.get(target, ROOT / "mappings")
    errors = 0
    for r in rules:
        try:
            q = be.convert(r)
        except backends.BackendError as e:
            print(f"FAIL  {e}", file=sys.stderr)
            errors += 1
            continue
        if target == "spl":
            header = f"``` {r.title} [{r.id}] ```"
        else:
            header = f"// {r.title} [{r.id}]"
        if out_dir:
            ext = "spl" if target == "spl" else "kql"
            dest = Path(out_dir) / target / f"{r.name}.{ext}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f"{header}\n{q}\n", encoding="utf-8")
        else:
            print(f"{header}\n{q}\n")
    return 1 if errors else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="detlab")
    p.add_argument("--rules", default=ROOT / "rules", type=Path)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lint")
    t = sub.add_parser("test")
    t.add_argument("--events", default=ROOT / "tests" / "events", type=Path)
    c = sub.add_parser("convert")
    c.add_argument("target", choices=["spl", "kql"])
    c.add_argument("-o", "--out-dir")
    args = p.parse_args(argv)

    try:
        rules = load_dir(args.rules)
    except SigmaError as e:
        print(f"FAIL  {e}")
        return 1

    if args.cmd == "lint":
        return cmd_lint(rules)
    if args.cmd == "test":
        return cmd_test(rules, args.events)
    return cmd_convert(rules, args.target, args.out_dir)


if __name__ == "__main__":
    sys.exit(main())
