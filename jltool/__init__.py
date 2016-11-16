#!/usr/bin/env python3
import json
import hashlib
import collections
import objectpath
import io
import textwrap
import csv
import sys
import itertools

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
    list: "list",
    type(None): "null"
}


class Deduper:
    """
    Assists in deduplicating objects, using objectpath queries to detect dupes.
    """

    def __init__(self, selector=''):
        "Creates a deduplicator with a given selector. If not given, uses md5."
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
        "Returns the number of duplicates encountered so far"
        return self.processed - len(self.seen)


def load_jsonlines(serial_line_iterable: ([str], _file))->[(dict, list)]:
    "Yield successive parsed objects from a JSONL iterable"
    for line in serial_line_iterable:
        if line and not line.isspace():
            yield json.loads(line)


def _hashobj(obj: (list, dict))->str:
    # Not intended to be resistant to deliberate collision. MD5 is not secure.
    ordered = json.dumps(obj, separators=(",", ":"), sort_keys=True)
    return hashlib.md5(ordered.encode()).hexdigest()


def objectpath_extract(obj: (list, dict), selector: str)->str:
    "Execute an objectpath expression to extract a hashable object"
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
        return _hashobj(obj)


def _indent_if(prettify: bool)->(int, None):
    'Purely a coding convenience.'
    return 1 if prettify else None


def dupes_cmd(file1, selector='', prettify=False, **_):
    "Dedupe assists in finding duplicate records, reporting duplicates by line"
    DD = Deduper(selector=selector)
    for seen, previous in dupes(load_jsonlines(file1), deduper=DD):
        print("Duplicate of line {0:3} at lines: {1}".format(seen, previous))
    else:
        print("Found ", DD.dupes, "duplicates.")


def dupes(record_iterator, deduper=None, selector='', prettify=False, **_):
    "Dedupe assists in finding duplicate records, reporting duplicates by line"
    DD = deduper or Deduper(selector=selector)
    for n, l in enumerate(record_iterator):
        seen = DD.search_priors(n, l)
        if seen:
            yield seen[0], seen[1:] + [n]


def diff_cmd(file1, file2, selector='', prettify=False, **_):
    "Print successive lines unique to the left or right file"
    f1lines = load_jsonlines(file1)
    f2lines = load_jsonlines(file2)
    for drxn, (lno, line) in diff(f1lines, f2lines, selector):
        pl = json.dumps(line, indent=_indent_if(prettify), sort_keys=True)
        for ln in pl.splitlines():
            dirlns = "<<<" if drxn == "L" else ">>>"
            print("{0}{1:4}:".format(dirlns, lno), ln)


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
        if 'lineno' not in locals():  # Patch over an UnboundLocalError
            lineno = 0
        print("Number of records:", lineno)
        print("Number of Duplicates:", DD.dupes)
    print("Common keys:", {key: key_types[key] for key in common_keys})
    for key, values in sorted(key_types.items()):
        if len(values) > 1:
            print("Inconsistent types for key '{0}': {1}".format(key, values))


def clean_cmd(file1, selector='', **_):
    "Deduplicate, order, and minimise objects in a JSONL file"
    for obj in dedupe(load_jsonlines(file1), selector=selector):
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        print(line)


def dedupe(iterator, selector=''):
    """
    Yield deduped objects from iterator, with optional selector to detect dupes
    """
    DD = Deduper(selector=selector)
    for l, obj in enumerate(iterator):
        if DD.search_priors(l, obj):
            continue
        yield obj


def grep_cmd(file1, expression='', selector='', **_):
    "Print lines matching expression from file1"
    for obj in grep(load_jsonlines(file1), expression, selector):
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        print(line)


def grep(iterator, expression, sel=''):
    "Yield successive matching objects from iterator, deduped by sel if given"
    DD = Deduper(selector=sel) if sel else None
    for l, obj in enumerate(iterator):
        if sel and DD.search_priors(l, obj):
            continue
        T = objectpath.Tree(obj)
        val = T.execute(expression)
        assert isinstance(val, bool), "Expression must evaluate to Boolean"
        if val:
            yield obj


def extract_cmd(file1, expression='', selector='', **_):
    "Print lines matching expression from file1"
    for obj in extract(load_jsonlines(file1), expression, selector):
        if isinstance(obj, (str, int, float, bool)):
            print(obj)
            continue
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        print(line)


def csv_cmd(file1, expressions=[], headers=[], selector='', **_):
    "Print comma-separated values matching the expression list"
    csvout = csv.writer(sys.stdout, dialect="unix")
    if headers:
        assert len(headers) == len(expressions), "Header list for CSV output provided but does not match selector list."
        csvout.writerow(headers)
    obj_iter = load_jsonlines(file1)
    many_iters = itertools.tee(obj_iter, len(expressions))
    streams = []
    for itr, expr in zip(many_iters, expressions):
        extr = extract(itr, expr, sel=selector)
        streams.append(extr)
    for row in zip(*streams):
        csvout.writerow(row)


def iota_cmd(file1, key, value_expression, selector='', **_):
    obj_stream = load_jsonlines(file1)
    for obj in iota(obj_stream, key, value_expression, sel=selector):
        line = json.dumps(obj, separators=(",", ":"), sort_keys=True)
        print(line)


def iota(iterator, key, value_expression, sel=''):
    """
    iota adds a new dynamically-constructed item to each object in a JSON-Lines stream

    (This is not especially useful as a Python function, of course)

    This 'new' item is stored as a key, and may replace an existing key.
    The value of the item is constructed with ObjectPath. To facilitate
    a common use-case, a special value '$.__iota' is made available within
    ObjectPath for this operation; this is removed afterwards from the object.
    The `$.__iota` value is equal to the zero-indexed line-number of the object.
    """
    DD = Deduper(selector=sel) if sel else None
    iotify = lambda d, j: dict(list(d.items()) + [("__iota", j)])
    i = 0
    for l, obj in enumerate(iterator):
        if sel and DD.search_priors(l, obj):
            continue  # i is not incremented for deduped items.
        obj = iotify(obj, i)  # shallow copy
        T = objectpath.Tree(obj)
        obj[key] = T.execute(value_expression)
        i += 1
        yield obj


def extract(iterator, expression, sel=''):
    "Extract uses an objectpath query to extract information from records."
    DD = Deduper(selector=sel) if sel else None
    for l, obj in enumerate(iterator):
        if sel and DD.search_priors(l, obj):
            continue
        T = objectpath.Tree(obj)
        val = T.execute(expression)
        if val is not None:
            yield val


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
    grepc = SP.add_parser("grep", help="Filter a JL file using objectpath.")
    grepc.set_defaults(func=grep_cmd)
    grepc.add_argument("expression", default='', type=str, help=_dd(
                       """Objectpath expression to select lines to emit. The \
                       expression takes place after deduplication by -s, if \
                       given, and the expression must evaluate to a boolean \
                       in objectpath."""))
    grepc.add_argument("-s", "--selector", default='', type=str, help=_dd(
                       """Objectpath selector to extract a representative, \
                       unique string from JSON objects for deduplication. \
                       If empty, deduping is not performed in this mode."""))
    grepc.add_argument("file1", type=argparse.FileType("r"),
                       help="File to read from")
    # == Extract ==
    extr = SP.add_parser("extract", help="Extract data from objects.")
    extr.set_defaults(func=extract_cmd)
    extr.add_argument("expression", default='', type=str, help=_dd(
                       """Objectpath expression to extract data to emit. The \
                       expression takes place after deduplication by -s, if \
                       given."""))
    extr.add_argument("-s", "--selector", default='', type=str, help=_dd(
                       """Objectpath selector to extract a representative, \
                       unique string from JSON objects for deduplication. \
                       If empty, deduping is not performed in this mode."""))
    extr.add_argument("file1", type=argparse.FileType("r"),
                       help="File to read from")
    # == CSV Export Mode ==
    csvm = SP.add_parser("csv", help="Extract many data as CSV columns")
    csvm.set_defaults(func=csv_cmd)
    csvm.add_argument("expressions", type=str, nargs="+", default=[], help=_dd(
                       """Objectpath expressions to extract 1+ columns \
                       to emit. The expressions take place after \
                       deduplication by -s, if given."""))
    csvm.add_argument("-s", "--selector", default='', type=str, help=_dd(
                       """Objectpath selector to extract a representative, \
                       unique string from JSON objects for deduplication. \
                       If empty, deduping is not performed in this mode."""))
    csvm.add_argument("-H", "--headers", default=[], type=str, nargs="+",
                      help="Optional headers to emit at start of CSV file.")
    csvm.add_argument("file1", type=argparse.FileType("r"),
                       help="File to read from")
    # == Iota Mode ==
    iotam = SP.add_parser("iota", help="Dynamically add a key:value pair to each object")
    iotam.set_defaults(func=iota_cmd)
    iotam.add_argument("key", type=str, help=_dd(
                       "Key to add new value as. May overwrite other keys."))
    iotam.add_argument("value_expression", type=str, help=_dd(
                        """Objectpath selector that can construct the new
                        value. This selector may assume the existence of a
                        special key, `$.__iota`, which is equal to the
                        (zero-indexed) position of the object in the JSON-Lines
                        file. So, the value will be `0` for the first object,
                        and `9` for the tenth object, etc.
                        """))
    iotam.add_argument("-s", "--selector", default='', type=str, help=_dd(
                       """Objectpath selector to extract a representative, \
                       unique string from JSON objects for deduplication. \
                       If empty, deduping is not performed in this mode."""))
    iotam.add_argument("file1", type=argparse.FileType("r"),
                       help="File to read from")

    # iota_cmd(file1, key, value_expression, selector='', **_)
    # == Execute ==
    args = P.parse_args()
    try:
        args.func(**vars(args))
    except BrokenPipeError:
        # For e.g. when piping to "head"
        # Probably in most cases this exception is
        # just noise, so bury it.
        pass


if __name__ == "__main__":
    _main()
