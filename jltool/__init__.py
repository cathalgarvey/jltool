#!/usr/bin/env python3
import json
import hashlib
import collections
import objectpath
import io
import textwrap

__version__ = "1.1.0"
_file = io.TextIOWrapper
_Hashable = collections.abc.Hashable
_dd = textwrap.dedent
_human_types = {
    str: "string",
    int: "integer",
    float: "float",
    bool: "boolean",
    dict: "object",
    list: "list"
}


class Deduper:
    def __init__(self, selector=''):
        self.selector = selector
        self.seen = {}
        self.processed = 0

    def search_priors(self, index: int, obj: (list, dict))->[int]:
        """
        Returns the set of previous indices for this object, recording index.
        """
        h = line_to_unique_id(obj, self.selector)
        was_seen = self.seen.setdefault(h, []).copy()
        self.seen[h].append(index)
        self.processed += 1
        return was_seen

    @property
    def dupes(self):
        return self.processed - len(self.seen)


def load_jsonlines(serial_line_iterable: ([str], _file))->[(dict, list)]:
    for line in serial_line_iterable:
        if line and not line.isspace():
            yield json.loads(line)


def hashobj(obj: (list, dict))->str:
    #Not intended to be resistant to deliberate collision. MD5 is not a secure hash.
    ordered = json.dumps(obj, separators=(",", ":"), sort_keys=True)
    return hashlib.md5(ordered.encode()).hexdigest()


def objectpath_extract(obj: (list, dict), selector: str)->str:
    T = objectpath.Tree(obj)
    val = T.execute(selector)
    assert isinstance(val, collections.abc.Hashable), \
        "Value extracted using objectpath must be hashable."
    return val


def line_to_unique_id(obj: (list, dict), selector: str='')->_Hashable:
    "Uses either objectpath selector string or dump md5(json.dumps(obj))"
    if selector:
        return objectpath_extract(obj, selector)
    else:
        return hashobj(obj)


def _indent_if(prettify: bool)->(int, None):
    'Purely a coding convenience.'
    return 1 if prettify else None


def dupes_cmd(file1, selector='', prettify=False, **_):
    "Dedupe assists in finding duplicate records, reporting duplicates by line."
    DD = Deduper(selector=selector)
    for seen, previous in dupes(load_jsonlines(file1), deduper=DD):
        print("Duplicate of line {0:3} at lines: {1}".format(seen, previous))
    else:
        print("Found ", DD.dupes, "duplicates.")


def dupes(record_iterator, deduper=None, selector='', prettify=False, **_):
    "Dedupe assists in finding duplicate records, reporting duplicates by line."
    DD = deduper or Deduper(selector=selector)
    for n, l in enumerate(record_iterator):
        seen = deduper.search_priors(n, l)
        if seen:
            yield seen[0], seen[1:] + [n]


def diff_cmd(file1, file2, selector='', prettify=False, **_):
    f1lines = load_jsonlines(file1)
    f2lines = load_jsonlines(file2)
    for dirxn, (lineno, line) in diff(f1lines, f2lines, selector):
        pl = json.dumps(line, indent=_indent_if(prettify), sort_keys=True)
        for line in pl.splitlines():
            print("{0}{1:4}:".format("<<<" if dirxn == "L" else ">>>", lineno), line)


def diff(iterator1, iterator2, selector=''):
    """
    Yield (direction, (lineno, line)) tuples, where direction is 'L' or 'R'

    iterator1 and iterator2 are unpacked into memory and fingerprints of each
    line are compared to get unique lines to either set.

    Duplicated lines are not factored into this method, yet. The last line with
    a given hash is retained for comparison, the rest are dropped. Deduplicate
    prior to use if this is a problem.
    """
    f1hashed = {line_to_unique_id(l, selector): (n, l)
                for n, l in enumerate(iterator1)}
    f2hashed = {line_to_unique_id(l, selector): (n, l)
                for n, l in enumerate(iterator2)}
    f1only = set(f1hashed).difference(f2hashed)
    f2only = set(f2hashed).difference(f1hashed)
    for lineno, line in sorted([f1hashed[h] for h in f1only]):
        yield "L", (lineno, line)
    for lineno, line in sorted([f2hashed[h] for h in f2only]):
        yield "R", (lineno, line)


def report_cmd(file1, selector='', **_):
    "Return some information about a JSONL file, reporting bad schema"
    DD = Deduper(selector=selector)
    linetypes = set()
    common_keys = set()
    key_types = {}
    for lineno, line in enumerate(load_jsonlines(file1), start=1):
        DD.search_priors(lineno, line)
        linetypes.add(type(line))
        if isinstance(line, dict):
            if lineno == 1:
                common_keys.update(line.keys())
            common_keys = common_keys.intersection(line.keys())
            for key, value in line.items():
                # For this key, add this valuetype to the type set.
                key_types.setdefault(
                    key, set([_human_types[type(value)]])
                    ).add(_human_types[type(value)])
    else:
        print("Number of records:", lineno)
        print("Number of Duplicates:", DD.dupes)
    print("Common keys:", {key: key_types[key] for key in common_keys})
    for key, values in key_types.items():
        if len(values) > 1:
            print("Inconsistent types for key '{0}': {1}".format(key, values))


def clean_cmd(file1, selector='', **_):
    "Deduplicate, order, and minimise objects in a JSONL file"
    for obj in dedupe(load_jsonlines(file1)):
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        print(line)


def dedupe(iterator, selector=''):
    DD = Deduper(selector=selector)
    for l, obj in enumerate(iterator):
        if DD.search_priors(l, obj):
            continue
        yield obj


def grep_cmd(file1, expression='', selector='', **_):
    for obj in grep(load_jsonlines(file1), expression, selector):
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        print(line)


def grep(iterator, expression='', selector=''):
    DD = Deduper(selector=selector) if selector else None
    for l, obj in enumerate(iterator):
        if selector and DD.search_priors(l, obj):
            continue
        T = objectpath.Tree(obj)
        val = T.execute(expression)
        assert isinstance(val, bool), "Objectpath expression must evaluate to Boolean"
        if val:
            yield obj


def _main():
    import argparse
    P = argparse.ArgumentParser(
      description="A simple JSON-Lines toolkit."
    )
    P.set_defaults(func=lambda *a, **k: print("No subcommand selected."))
    SP = P.add_subparsers()
    # == Diff between two datasets ==
    diff = SP.add_parser("diff",
                         help="Diff two JSON-Lines files.")
    diff.set_defaults(func=diff_cmd)
    diff.add_argument("file1", type=argparse.FileType("r"),
                      help="File to diff")
    diff.add_argument("file2", type=argparse.FileType("r"),
                      help="File to diff")
    diff.add_argument("-s", "--selector", default='', type=str, help=_dd(
                      """Objectpath selector to extract a representative, \
                         unique string from JSON objects. If unspecified, \
                         then objects are hashed as normalised JSON to get a \
                         unique value."""))
    diff.add_argument("--prettify", default=False, action="store_true",
                      help="Bigger but more readable output.")
    # == Deduplication ==
    dupe = SP.add_parser("dupes", help="Find and report duplicate lines.")
    dupe.set_defaults(func=dupes_cmd)
    dupe.add_argument("file1", type=argparse.FileType("r"),
                      help="File to diff")
    dupe.add_argument("-s", "--selector", default='', type=str, help=_dd(
                      """Objectpath selector to extract a representative, \
                      unique string from JSON objects. If unspecified, then \
                      objects are hashed as normalised JSON to get a unique \
                      value."""))
    dupe.add_argument("--prettify", default=False, action="store_true",
                      help="Bigger but more readable output.")
    # == Report ==
    report = SP.add_parser("report", help="Give a report for a JSONL file.")
    report.set_defaults(func=report_cmd)
    report.add_argument("file1", type=argparse.FileType("r"),
                        help="File to build report on.")
    report.add_argument("-s", "--selector", default='', type=str, help=_dd(
                        """Objectpath selector to extract a representative, \
                        unique string from JSON objects. If unspecified, then \
                        objects are hashed as normalised JSON to get a unique \
                        value. Influences duplicate detection for reports."""))
    # == Clean ==
    clean = SP.add_parser("clean", help="Clean, dedupe, & minimise a file.")
    clean.set_defaults(func=clean_cmd)
    clean.add_argument("-s", "--selector", default='', type=str, help=_dd(
                       """Objectpath selector to extract a representative, \
                       unique string from JSON objects. If unspecified, then \
                       objects are hashed as normalised JSON to get a unique \
                       value."""))
    clean.add_argument("file1", type=argparse.FileType("r"),
                       help="File to read from")
    # == Grep ==
    clean = SP.add_parser("grep", help="Filter a JL file using objectpath.")
    clean.set_defaults(func=grep_cmd)
    clean.add_argument("expression", default='', type=str, help=_dd(
                       """Objectpath expression to select lines to emit. The \
                       expression takes place after deduplication by -s, if \
                       given, and the expression must evaluate to a boolean \
                       in objectpath."""))
    clean.add_argument("-s", "--selector", default='', type=str, help=_dd(
                       """Objectpath selector to extract a representative, \
                       unique string from JSON objects. If unspecified, then \
                       objects are hashed as normalised JSON to get a unique \
                       value."""))
    clean.add_argument("file1", type=argparse.FileType("r"),
                       help="File to read from")
    # == Execute ==
    args = P.parse_args()
    args.func(**vars(args))


if __name__ == "__main__":
    _main()
