# JLTool - Tools for JSON-Lines Records
by Cathal Garvey, ©2016, Released under terms of the GNU AGPLv3 or later

The [JSON-Lines format](http://jsonlines.org) is a clean alternative to
comma-separated values as a means to store data records in a scaleable, flat
manner, for cases where a database is too much but a flat JSON file is
inefficient.

JLTool is a tool for working with JSON-Lines records; it assists in schema
validation, duplicate detection, de-duplication and normalisation, and
'grepping' using objectpath queries.

[ObjectPath](http://objectpath.org/) is supported for most operations; in
particular, for fetching a unique, representative ID from objects for purposes
of deduplication or diffing documents. For grepping, ObjectPath can be used to
query for matching rows.

Installing JLTool with `python3 setup.py install` or `pip install jl` will install
the `jltool` command-line tool, which is the primary intended purpose. However,
for operations on files the subcommands of `jltool` are all available in the `jltool`
import if desired. Just open it in `ipython` and take a look at the docs on the
command functions for more information.

### Usage Examples
Say you have a JSON-Lines file '`records.jsonl`' containing records that look like this:

```json
{"type": "email", "value": "cathal@isgre.at", "meta": {"foo": "bar"} }
```

..which is similar enough to the job I needed doing, when I wrote `jltool`. :)

Many of the commands use [objectpath](http://objectpath.org), as an optional
way of selecting or uniquifying records. Check the documentation there for info.

#### Get a Report
The `report` subcommand returns a report on the size and structure of a file,
including reporting common keys and keys that have an uncertain type/schema:

```bash
$ jltool report records.jsonl
Number of records: 13
Number of Duplicates: 0
Common keys: {'type': {'string'}, 'value': {'string'}, 'meta': {'object'}}
```

#### Filtering Reports
The `grep` subcommand allows the use of objectpath queries to filter a JSONL file.
The objectpath query must evaluate to a boolean. If desired, deduplication
may be done prior to selection, by passing a `-s` selector by which to deduplicate
records, but if no `-s` selector is given then no deduplication is performed.

```bash
$ cat records.jsonl
{"type": "email", "value": "foo@bar.com", "meta": {}}
{"type": "twitter", "value": "onetruecathal", "meta": {"awesomeness": 9001}}
{"type": "email", "value": "baz@qux.tld", "meta": {"lol": "wut"}}
$ jltool grep '$.type is "twitter"' records.jsonl
{"type": "twitter", "value": "onetruecathal", "meta": {"awesomeness": 9001}}
```

#### Difference Between Two files
The `diff` command reports records that are present in one file and not the
other. This is done without regard to order, and hashes or representative
extracted strings are stored in memory during this operation, so for very large
files this may consume a lot of RAM.

By default, this uses the hash of a normalised form of each line as a fingerprint,
but this is obviously not ideal in cases where metadata, timestamps or other
bits may cause two functionally identical records to appear different.

To fix this, you can use objectpath queries to extract a representative string
according to your needs, by passing an objectpath query with the `-s` flag.
This is also true of many ensuing commands, not just `diff`.

```bash
$ # Observe query that pulls out type and value for a unique reference..
$ jltool diff -s '$.type + ":" + $.value' records.jsonl others.jsonl
<<<  50: {"meta": {"job": "http://www.lol.org"}, "type": "email", "value": "kboo@lol.foo"}
<<<  51: {"meta": {"job": "http://www.baaa.com"}, "type": "email", "value": "adonis@rap.com"}
>>>   0: {"meta": {"job": "http://nonsense.com/"}, "type": "twitter", "value": "nonsense"}
```

#### Deduplicate
The `dedupe` command reports duplicate records. This is where objectpath queries
may become relevant, because the same "record" may have different metadata
attached, and may therefore appear to be different if simply serialised as
ordered JSON, which is the default.

Note that due to the linewise way reports are made, this may issue notifications
of duplicates several times as additional duplicates appear, as in the below
example.

```bash
$ jltool dedupe records.jsonl
Duplicate of line   0 at lines: [13]
Duplicate of line   2 at lines: [15]
Duplicate of line   2 at lines: [15, 28]
Duplicate of line   5 at lines: [18, 31]
Duplicate of line  10 at lines: [23, 36, 49]
Duplicate of line  12 at lines: [25, 38, 51]
Found  39 duplicates.
```

#### Clean
The `clean` subcommand normalises, minifies, and deduplicates jsonl files.
It should be used with similar care to other optional-query commands as, if
a query is incorrectly formed, it may result in loss of data.

```bash
$ ls -lah
drwxr-sr-x 4 cathal cathal 4.0K May 31 16:39 .
drwxrwxr-x 3 cathal cathal 4.0K May 30 19:52 ..
-rw-rw-r-- 1 cathal cathal  10K May 31 15:43 records.jsonl
$ jltool clean records.jsonl dedupe.jsonl
$ ls -lah
drwxr-sr-x 4 cathal cathal 4.0K May 31 16:39 .
drwxrwxr-x 3 cathal cathal 4.0K May 30 19:52 ..
-rw-rw-r-- 1 cathal cathal 2.4K May 31 16:42 dedupe.jsonl
-rw-rw-r-- 1 cathal cathal  10K May 31 15:43 records.jsonl
```
