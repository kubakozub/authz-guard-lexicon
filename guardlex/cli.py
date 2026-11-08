"""Command line interface.

    authz-guard-lexicon check FILE        is this function body guarded, and by what
    authz-guard-lexicon rules             every rule, and the one line reason it exists
    authz-guard-lexicon anon FILE         handler registrations reachable anonymously
    authz-guard-lexicon selftest          run the two sided controls

Exit codes on `check`:
    0  a guard was found
    1  no guard was found
    2  usage or input error
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .rules import (CONTEXT_RULES, RULES, chia_p2p_handlers,
                    django_anonymous_views, go_unauthed_handlers,
                    grape_anonymous_routes, is_guarded,
                    rails_anonymous_actions, selftest, selftest_js_pairs)

EXIT_GUARDED = 0
EXIT_UNGUARDED = 1
EXIT_ERROR = 2

#: Which language probe to use, by extension. There is no sniffing: a caller
#: that guesses the language from the extension alone is how every .ts and .go
#: file once got parsed with the Ruby rules.
BY_EXTENSION = {
    ".rb": ("ruby", (("rails", rails_anonymous_actions),
                     ("grape", grape_anonymous_routes))),
    ".py": ("python", (("django", django_anonymous_views),
                       ("chia", chia_p2p_handlers))),
    ".go": ("go", (("go", go_unauthed_handlers),)),
}


def _read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def command_check(args) -> int:
    if args.path != "-" and not os.path.isfile(args.path):
        print("not a file: %s" % args.path, file=sys.stderr)
        return EXIT_ERROR
    body = _read(args.path)
    guarded, rule = is_guarded(body, admin_counts=not args.no_admin)
    if args.json:
        print(json.dumps({"guarded": guarded, "rule": rule,
                          "admin_counts": not args.no_admin}))
    elif guarded:
        print("guarded by %s" % rule)
    else:
        print("no recognised guard")
    return EXIT_GUARDED if guarded else EXIT_UNGUARDED


def command_rules(args) -> int:
    if args.json:
        print(json.dumps({
            "guards": [{"name": n, "why": w} for n, _, w in RULES],
            "context": [{"name": n, "why": w} for n, _, w in CONTEXT_RULES],
        }, indent=2))
        return EXIT_GUARDED
    print("GUARDS, in the order is_guarded consults them\n")
    for name, _, why in RULES:
        print("  %-16s %s" % (name, why))
    print("\nNOT GUARDS, kept separate because confusing them with guards is the")
    print("mistake each one was added to prevent\n")
    for name, _, why in CONTEXT_RULES:
        print("  %-16s %s" % (name, why))
    print("\nThe long version of each is the comment above its pattern in "
          "guardlex/rules.py,\nnaming the project and the case that forced it.")
    return EXIT_GUARDED


def command_anon(args) -> int:
    if not os.path.isfile(args.path):
        print("not a file: %s" % args.path, file=sys.stderr)
        return EXIT_ERROR
    extension = os.path.splitext(args.path)[1].lower()
    if extension not in BY_EXTENSION:
        print("no probe for %s. Known: %s"
              % (extension or "(no extension)", ", ".join(sorted(BY_EXTENSION))),
              file=sys.stderr)
        return EXIT_ERROR
    language, probes = BY_EXTENSION[extension]
    text = _read(args.path)
    found = []
    for label, probe in probes:
        try:
            for item in probe(text) or []:
                found.append((label, item))
        except Exception as error:  # noqa: BLE001
            print("  %s probe failed: %s" % (label, error), file=sys.stderr)
    if args.json:
        print(json.dumps([{"probe": p, "found": list(map(str, i))
                           if isinstance(i, tuple) else str(i)}
                          for p, i in found], indent=2))
        return EXIT_GUARDED if not found else EXIT_UNGUARDED
    if not found:
        print("%s: no anonymous registration found" % language)
        print("A zero from an analyzer that does not speak the target's dialect "
              "is not a result. Check that this file really uses an idiom the "
              "tables below know: authz-guard-lexicon rules")
        return EXIT_GUARDED
    for label, item in found:
        print("  [%s] %s" % (label, item))
    return EXIT_UNGUARDED


def command_selftest(args) -> int:
    bad = selftest()
    pairs = selftest_js_pairs()
    if bad or pairs:
        return EXIT_UNGUARDED
    return EXIT_GUARDED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="authz-guard-lexicon",
        description="What counts as an authorization check, across five languages.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="is this function body guarded, and by what")
    check.add_argument("path", help="file to read, or - for stdin")
    check.add_argument("--no-admin", action="store_true",
                       help="do not count an administrative gate as a guard")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=command_check)

    listing = sub.add_parser("rules", help="every rule and why it exists")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(func=command_rules)

    anon = sub.add_parser("anon", help="registrations reachable anonymously")
    anon.add_argument("path")
    anon.add_argument("--json", action="store_true")
    anon.set_defaults(func=command_anon)

    test = sub.add_parser("selftest", help="run the two sided controls")
    test.set_defaults(func=command_selftest)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except OSError as error:
        print("read failed: %s" % error, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
