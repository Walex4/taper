"""Declared operations: a typed operation defined in a file, not in Python.

The adoption cost of Rule 1 is that every kind of thing an agent might do
needs an adapter, and an adapter is Python. This module makes an operation a
JSON file the broker compiles into the same `Operation` and `Adapter` a
hand-written one produces. The agent sees no difference; neither does policy.

DESIGN.md §7 "Declared operations" records the decision and its four
conditions. This file enforces them:

  1. A placeholder is one thing. An argv element is a literal or exactly
     "{field}"; a SQL statement is fixed text with every field bound; an
     HTTP path is segments. Every declared string value must match the same
     alphabet ssh.exec's arguments must match, so shell metacharacters and
     whitespace are inexpressible before any pattern of the spec's own.
     verified-by: tests/test_taper.py::TestDeclared::test_a_placeholder_inside_a_literal_is_refused_at_load
     verified-by: tests/test_taper.py::TestDeclared::test_a_value_outside_the_safe_alphabet_is_inexpressible
  2. A field may not be a command. argv[0] is a literal and not an
     interpreter or wrapper; no placeholder follows a shell-style flag; an
     optional field's placeholder never sits directly after a flag.
     verified-by: tests/test_taper.py::TestDeclared::test_a_free_field_after_a_shell_flag_is_refused_at_load
     verified-by: tests/test_taper.py::TestDeclared::test_an_interpreter_as_the_program_is_refused_at_load
  3. Layer 2 is named or its absence is loud. A spec carries `layer2` or is
     marked layer-1-only, and the CLI says so for every grant that includes it.
     verified-by: tests/test_taper.py::TestDeclared::test_a_spec_without_layer2_is_marked_layer_1_only
  4. The grant commits to the definition. `definition_hash()` is what the
     root block signs and what the broker compares before deriving anything.
     verified-by: tests/test_taper.py::TestDeclared::test_an_edited_definition_no_longer_matches_the_grant

Free text is the one exception to condition 1, and it is placed, not
filtered. A field of type "text" may hold a space, a quote or a newline, and
the compiler admits it only where nothing parses it: a bound SQL parameter, an
HTTP query value the broker percent-encodes, or an HTTP body the broker writes
whole or JSON-encodes. It is refused at load in argv, in a host, in a path
segment, in a database name - anywhere a value becomes syntax. A text field is
content, not authority: it is not a policy attribute, for the same reason
pg.query's statement is not one.
    verified-by: tests/test_taper.py::TestBoundText::test_a_text_field_is_refused_everywhere_it_would_be_parsed
    verified-by: tests/test_taper.py::TestBoundText::test_a_text_field_is_not_a_policy_attribute

What a declaration cannot express is judgement. Anything that derives an
attribute from a value - pg.query classifying a statement - stays a Python
adapter. If a spec needs a conditional, a default computed from another
field, or a field inside a literal, the answer is a Python adapter, not a
richer grammar. The grammar is frozen here on purpose.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import ops
from .adapters.base import Adapter, ExecPlan
from .ops import Field, Operation, OperationError

# ----------------------------------------------------------------- the grammar

# Two segments, one dot. The MCP server turns the dot into an underscore and
# back by replacing the FIRST underscore, so the first segment may not contain
# one; the second may.
_NAME = re.compile(r"^[a-z][a-z0-9]{0,31}\.[a-z][a-z0-9_]{0,31}\Z")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}\Z")
_PLACEHOLDER = re.compile(r"^\{([a-z][a-z0-9_]{0,31})\}\Z")
# The alphabet every declared string value must fit, before its own pattern.
# Identical to ssh.exec's argument alphabet: no whitespace, no quotes, no
# shell metacharacters, no newline. What is not in this class is not
# representable in a request at all.
SAFE_VALUE = ops._SAFE_ARG
_SECRET_REF = re.compile(r"^[a-z][a-z0-9_.\-]{0,63}\Z")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}\Z")
_TABLE = re.compile(r"^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}\Z")

KINDS = ("process", "ssh", "sql", "http")
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
FIELD_TYPES = ("string", "integer", "text")
# A text field's default ceiling. A bound value is inert, not free: a field
# that can carry a megabyte is a field that can carry a megabyte to the target.
TEXT_MAX_DEFAULT = 4000
TEXT_MAX_CEILING = 65536
# Control characters a text value may not carry. Newline, carriage return and
# tab are text; NUL, escapes and the rest are not, and a NUL in particular is
# where C-string and length-prefixed consumers start to disagree.
_TEXT_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# HTTP query keys and literal values. Literal values are percent-encoded by the
# broker, so a space or a comma in one is data; braces stay reserved for the
# placeholder syntax so a literal can never be mistaken for one.
_QUERY_KEY = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}\Z")
_QUERY_LITERAL = re.compile(r"^[\x20-\x7a\x7c\x7e]{0,1024}\Z")
# Headers a credential may be sent in. Anything that frames the request itself
# is refused: a credential named "Host" or "Content-Length" is not a
# credential, it is a way to rewrite where and how much.
_HEADER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9\-]{0,63}\Z")
_FRAMING_HEADERS = frozenset({
    "host", "content-length", "content-type", "transfer-encoding", "connection",
    "cookie", "te", "upgrade", "trailer", "keep-alive", "proxy-authorization",
    "expect"})
_AUTH_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9\-]{0,31}\Z")
MAX_JSON_DEPTH = 8

# Flags after which a value is a program for something else to interpret.
# A placeholder after any of these is a command in a field, whatever the
# field is called.
SHELL_FLAGS = frozenset({
    "-c", "-e", "-E", "--command", "--cmd", "--exec", "--eval", "--script",
    "-exec", "--run", "--execute", "--filter", "--jsonpath", "-p", "--template",
    "--go-template", "--query", "-q",
})
# Programs that exist to run other programs or to interpret text. An argv[0]
# from this set makes the rest of argv a program, and that program's whole
# surface the policy surface - the unbounded auditing Rule 1 refuses.
INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "cmd", "cmd.exe",
    "powershell", "pwsh", "python", "python2", "python3", "perl", "ruby", "node",
    "nodejs", "deno", "bun", "php", "lua", "tclsh", "awk", "gawk", "sed",
    "env", "eval", "exec", "xargs", "sudo", "doas", "su", "nice", "nohup",
    "timeout", "watch", "ssh", "scp", "sftp", "rsync", "find", "make", "sh.exe",
    "busybox", "chroot", "nsenter", "unshare", "docker-compose", "script",
})

MAX_SPEC_BYTES = 64 * 1024


class SpecError(ValueError):
    """The declaration is refused. The message names the rule and the place."""


# ------------------------------------------------------------------ the parts

@dataclass(frozen=True)
class DeclaredField:
    name: str
    type: str                     # "string" | "integer" | "text"
    required: bool
    pattern: re.Pattern | None
    enum: frozenset | None
    lo: int | None
    hi: int | None
    describe: str
    max_length: int | None = None

    def accepts(self, value: Any) -> bool:
        if self.type == "text":
            # Free text, bounded: a length, no control characters but line
            # breaks and tabs, and valid Unicode (a lone surrogate would fail
            # to encode at the far end of the socket rather than here).
            # verified-by: tests/test_taper.py::TestBoundText::test_text_accepts_prose_and_refuses_control_characters
            if not isinstance(value, str) or len(value) > (self.max_length or TEXT_MAX_DEFAULT):
                return False
            if _TEXT_FORBIDDEN.search(value):
                return False
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                return False
            return True
        if self.type == "string":
            if not isinstance(value, str) or not SAFE_VALUE.match(value):
                return False
            if self.enum is not None:
                return value in self.enum
            if self.pattern is not None:
                return bool(self.pattern.match(value))
            return True
        if self.type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                return False
            if self.lo is not None and value < self.lo:
                return False
            if self.hi is not None and value > self.hi:
                return False
            return True
        return False

    def json_schema(self) -> dict:
        if self.type == "text":
            d: dict[str, Any] = {"type": "string",
                                 "maxLength": self.max_length or TEXT_MAX_DEFAULT}
            if self.describe:
                d["description"] = self.describe
            return d
        d = {"type": self.type}
        if self.describe:
            d["description"] = self.describe
        if self.enum is not None:
            d["enum"] = sorted(self.enum)
        if self.lo is not None:
            d["minimum"] = self.lo
        if self.hi is not None:
            d["maximum"] = self.hi
        return d


@dataclass(frozen=True)
class Layer2:
    enforced_by: str
    check: str


@dataclass
class Declaration:
    """A compiled spec. Everything the broker needs, and the hash the grant
    commits to."""

    name: str
    summary: str
    kind: str
    fields: dict[str, DeclaredField]
    spec: dict                          # as loaded, after validation
    layer2: Layer2 | None
    source: str = ""                    # path, for messages
    warnings: list[str] = field(default_factory=list)

    def definition_hash(self) -> str:
        return definition_hash(self.spec)

    def segment_fields(self) -> frozenset[str]:
        """Fields that fill an HTTP path segment, and so must be one."""
        if self.kind != "http":
            return frozenset()
        names = set()
        for seg in self.spec.get("path", []):
            m = _PLACEHOLDER.match(seg) if isinstance(seg, str) else None
            if m:
                names.add(m.group(1))
        return frozenset(names)

    def operation(self) -> Operation:
        segments = self.segment_fields()

        def validator(f: DeclaredField):
            if f.name not in segments:
                return f.accepts
            # A path field is refused at validation, where every other
            # malformed value is refused and audited, and again at planning.
            # verified-by: tests/test_taper.py::TestHttpDeclared::test_a_path_field_fills_exactly_one_segment
            return lambda v: f.accepts(v) and one_segment(str(v))

        return Operation(
            name=self.name,
            summary=self.summary,
            fields=tuple(
                Field(f.name, int if f.type == "integer" else str,
                      required=f.required, validator=validator(f), describe=f.describe)
                for f in self.fields.values()),
        )

    def json_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {n: f.json_schema() for n, f in self.fields.items()},
            "required": [n for n, f in self.fields.items() if f.required],
        }

    def policy_attributes(self) -> tuple[str, ...]:
        # Every field is a policy attribute. A field the grant does not name
        # is refused by the broker as unconstrained; a field the grant does
        # not care about is `any`, and the policy-pressure warning says so.
        # That is the intended pressure, not a nuisance.
        #
        # Except text. A text field is what an operation carries, not where it
        # goes: the message, not the recipient. It can only be bound, so it
        # cannot change the operation; constraining it would mean a grant
        # whose one honest value is `any`, and a warning at every mint that
        # trains operators to ignore the warning.
        # verified-by: tests/test_taper.py::TestBoundText::test_a_text_field_is_not_a_policy_attribute
        return tuple(n for n, f in self.fields.items() if f.type != "text")

    def text_fields(self) -> frozenset[str]:
        return frozenset(n for n, f in self.fields.items() if f.type == "text")

    def layer1_only(self) -> bool:
        return self.layer2 is None


# ------------------------------------------------------------------- the hash

_DOC_KEYS = ("summary", "layer2")


def canonical(spec: dict) -> bytes:
    """The bytes the grant commits to: the definition, minus its prose.

    `summary`, `layer2` and every field's `describe` are documentation. An
    operator fixing a typo in the layer-2 note should not invalidate every
    grant that names the operation; changing what the operation DOES should.
    """
    body = {k: v for k, v in spec.items() if k not in _DOC_KEYS}
    body["fields"] = {
        n: {k: v for k, v in f.items() if k != "describe"}
        for n, f in spec.get("fields", {}).items()
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def definition_hash(spec: dict) -> str:
    return hashlib.sha256(b"\x00taper-definition\x00" + canonical(spec)).hexdigest()


# --------------------------------------------------------------- the compiler

def _fail(where: str, why: str) -> SpecError:
    return SpecError(f"{where}: {why}")


def _expect_str(where: str, d: dict, key: str, required: bool = True) -> str | None:
    v = d.get(key)
    if v is None:
        if required:
            raise _fail(where, f"missing {key!r}")
        return None
    if not isinstance(v, str):
        raise _fail(where, f"{key!r} must be a string")
    return v


def _compile_fields(where: str, raw: Any) -> dict[str, DeclaredField]:
    if not isinstance(raw, dict) or not raw:
        raise _fail(where, "'fields' must be a non-empty object")
    out: dict[str, DeclaredField] = {}
    for name, fd in raw.items():
        fw = f"{where}.fields.{name}"
        if not _FIELD_NAME.match(name):
            raise _fail(fw, "field names are lower-case identifiers")
        if not isinstance(fd, dict):
            raise _fail(fw, "must be an object")
        unknown = set(fd) - {"type", "required", "pattern", "enum", "min", "max", "describe",
                             "max_length"}
        if unknown:
            raise _fail(fw, f"unknown keys {sorted(unknown)}")
        ftype = _expect_str(fw, fd, "type")
        if ftype not in FIELD_TYPES:
            raise _fail(fw, "type must be 'string', 'integer' or 'text'")
        required = fd.get("required", True)
        if not isinstance(required, bool):
            raise _fail(fw, "'required' must be true or false")
        describe = _expect_str(fw, fd, "describe", required=False) or ""
        pattern = enum = lo = hi = max_length = None
        if "max_length" in fd and ftype != "text":
            raise _fail(fw, "'max_length' applies to text fields")
        if ftype == "text":
            if set(fd) & {"pattern", "enum", "min", "max"}:
                raise _fail(fw, "a text field is free text: no pattern, enum, min or max. "
                            "If the value has a shape, it is a string field")
            ml = fd.get("max_length", TEXT_MAX_DEFAULT)
            if isinstance(ml, bool) or not isinstance(ml, int) or not 1 <= ml <= TEXT_MAX_CEILING:
                raise _fail(fw, f"'max_length' is an integer from 1 to {TEXT_MAX_CEILING}")
            max_length = ml
        elif ftype == "string":
            if "min" in fd or "max" in fd:
                raise _fail(fw, "min/max apply to integer fields")
            if "pattern" in fd and "enum" in fd:
                raise _fail(fw, "use 'pattern' or 'enum', not both")
            if "pattern" in fd:
                p = fd["pattern"]
                if not isinstance(p, str) or not p or len(p) > 512:
                    raise _fail(fw, "'pattern' must be a non-empty string")
                try:
                    pattern = re.compile(r"\A(?:" + p + r")\Z")
                except re.error as exc:
                    raise _fail(fw, f"'pattern' does not compile: {exc}") from None
            if "enum" in fd:
                e = fd["enum"]
                if (not isinstance(e, list) or not e
                        or not all(isinstance(x, str) and SAFE_VALUE.match(x) for x in e)):
                    raise _fail(fw, "'enum' must be a non-empty list of safe strings")
                enum = frozenset(e)
        else:
            if "pattern" in fd or "enum" in fd:
                raise _fail(fw, "pattern/enum apply to string fields")
            for k in ("min", "max"):
                if k in fd and (isinstance(fd[k], bool) or not isinstance(fd[k], int)):
                    raise _fail(fw, f"{k!r} must be an integer")
            lo, hi = fd.get("min"), fd.get("max")
            if lo is not None and hi is not None and lo > hi:
                raise _fail(fw, "min exceeds max")
        out[name] = DeclaredField(name, ftype, required, pattern, enum, lo, hi, describe,
                                  max_length)
    return out


def _placeholder(element: Any) -> str | None:
    """The field an element names, or None for a literal. Anything that
    contains a brace but is not exactly one placeholder is refused: a field
    inside a literal is the composition the grammar forbids."""
    if not isinstance(element, str):
        raise SpecError("template elements must be strings")
    m = _PLACEHOLDER.match(element)
    if m:
        return m.group(1)
    if "{" in element or "}" in element:
        raise SpecError(f"{element!r}: a placeholder is a whole element, "
                        f"never part of a literal")
    return None


def _compile_template(where: str, raw: Any, fields: dict[str, DeclaredField],
                      first_is_program: bool) -> list[tuple[str, str]]:
    """Validate an argv-style template. Returns [(kind, value)] where kind is
    'lit' or 'field'. Enforces condition 2."""
    if not isinstance(raw, list) or not raw:
        raise _fail(where, "must be a non-empty list")
    out: list[tuple[str, str]] = []
    prev_literal: str | None = None
    for i, element in enumerate(raw):
        try:
            name = _placeholder(element)
        except SpecError as exc:
            raise _fail(f"{where}[{i}]", str(exc)) from None
        if name is None:
            if not SAFE_VALUE.match(element) and not (i == 0 and first_is_program):
                raise _fail(f"{where}[{i}]", f"literal {element!r} is outside the "
                            f"safe alphabet; a literal that needs a space or a "
                            f"quote is a shell fragment")
            if i == 0 and first_is_program:
                base = element.rsplit("/", 1)[-1]
                if base in INTERPRETERS:
                    raise _fail(f"{where}[0]", f"{element!r} is an interpreter or a "
                                f"wrapper; its arguments would be a program, and "
                                f"that program's surface the policy surface. Declare "
                                f"the thing it would run, or write a Python adapter.")
            out.append(("lit", element))
            prev_literal = element
            continue
        if i == 0 and first_is_program:
            raise _fail(f"{where}[0]", "the program is a literal, never a field")
        if name not in fields:
            raise _fail(f"{where}[{i}]", f"placeholder names no field: {name!r}")
        if fields[name].type == "text":
            raise _fail(f"{where}[{i}]", _TEXT_PLACED)
        if prev_literal is not None:
            if prev_literal in SHELL_FLAGS:
                raise _fail(f"{where}[{i}]", f"a field after {prev_literal!r} is a "
                            f"command in a field: whatever the value, something "
                            f"will interpret it. Refused.")
            if prev_literal.startswith("-") and not fields[name].required:
                raise _fail(f"{where}[{i}]", f"optional field {name!r} directly after "
                            f"flag {prev_literal!r}: when absent, the flag would "
                            f"dangle and take the next element as its value. Make "
                            f"the field required or move the flag.")
        out.append(("field", name))
        prev_literal = None
    return out


def one_segment(value: str) -> bool:
    """A value that stays one path segment through normalization: no slash,
    no backslash, no percent-escape (which decodes into either), and not a
    dot-segment or empty."""
    return not ("/" in value or "\\" in value or "%" in value
                or value in ("", ".", ".."))


_TEXT_PLACED = ("a text field is free text and may only be bound - a SQL "
                "param, an HTTP query value, an HTTP body - never placed where "
                "it is parsed: argv, a host, a path segment, a database name")


def _compile_query(where: str, raw: Any, fields: dict[str, DeclaredField],
                   used: set[str]) -> list[tuple[str, str]]:
    """{"key": "literal" | "{field}", ...} or [["key", value], ...] for a
    repeated key. Keys are literal. A value is a literal, percent-encoded by
    the broker, or one whole field - string, integer or text, since the
    broker encodes whatever it holds. Returns [(key, value)] in order.
    verified-by: tests/test_taper.py::TestHttpDeclared::test_query_values_are_encoded_and_keys_are_fixed
    """
    if isinstance(raw, dict):
        pairs = list(raw.items())
    elif isinstance(raw, list) and all(isinstance(p, list) and len(p) == 2 for p in raw):
        pairs = [(k, v) for k, v in raw]
    else:
        raise _fail(where, "'query' is an object of key: value, or a list of "
                    "[key, value] pairs when a key repeats")
    if not pairs or len(pairs) > 32:
        raise _fail(where, "'query' names 1 to 32 parameters")
    out: list[tuple[str, str]] = []
    for key, value in pairs:
        kw = f"{where}.{key}"
        if not isinstance(key, str) or not _QUERY_KEY.match(key):
            raise _fail(kw, "a query key is a literal name")
        if not isinstance(value, str):
            raise _fail(kw, "a query value is a string: a literal or \"{field}\"")
        try:
            name = _placeholder(value)
        except SpecError as exc:
            raise _fail(kw, str(exc)) from None
        if name is None:
            if not _QUERY_LITERAL.match(value):
                raise _fail(kw, "a literal query value is printable ASCII, braces aside")
        else:
            if name not in fields:
                raise _fail(kw, f"placeholder names no field: {name!r}")
            used.add(name)
        out.append((key, value))
    return out


def _compile_json_body(where: str, raw: Any, fields: dict[str, DeclaredField],
                       used: set[str], depth: int = 0) -> None:
    """A JSON template. Structure is fixed by the spec; a string that is
    exactly "{field}" is that field's value, JSON-encoded by the broker, so a
    quote in a text value is a character in a string and never the end of
    one. Any other string is a literal. An optional field may fill an object
    member, which is omitted when the field is absent; it may not be an array
    element, where absence would shift every index after it.
    verified-by: tests/test_taper.py::TestHttpDeclared::test_a_json_body_is_a_fixed_structure_with_encoded_values
    """
    if depth > MAX_JSON_DEPTH:
        raise _fail(where, f"a JSON body nests at most {MAX_JSON_DEPTH} deep")
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or "{" in k or "}" in k:
                raise _fail(where, "a JSON key is a literal, never a field")
            _compile_json_body(f"{where}.{k}", v, fields, used, depth + 1)
    elif isinstance(raw, list):
        for i, v in enumerate(raw):
            name = _PLACEHOLDER.match(v).group(1) if isinstance(v, str) and _PLACEHOLDER.match(v) else None
            if name is not None and name in fields and not fields[name].required:
                raise _fail(f"{where}[{i}]", "an optional field may not be an array "
                            "element; its absence would move every element after it")
            _compile_json_body(f"{where}[{i}]", v, fields, used, depth + 1)
    elif isinstance(raw, str):
        m = _PLACEHOLDER.match(raw)
        if m:
            if m.group(1) not in fields:
                raise _fail(where, f"placeholder names no field: {m.group(1)!r}")
            used.add(m.group(1))
    elif raw is None or isinstance(raw, (bool, int, float)):
        pass
    else:
        raise _fail(where, "a JSON body holds objects, arrays, strings, numbers, "
                    "true, false and null")


def _compile_authorization(where: str, raw: Any) -> dict | None:
    """A secret ref (sent verbatim as Authorization, as before), or
    {"ref", "header"?, "scheme"?}: the header a service reads its key from,
    and a scheme word the broker writes in front of the secret.
    verified-by: tests/test_taper.py::TestHttpDeclared::test_a_credential_header_may_not_frame_the_request
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        if not _SECRET_REF.match(raw):
            raise _fail(where, "'authorization' is a secret ref")
        return {"ref": raw, "header": "Authorization", "scheme": None}
    if not isinstance(raw, dict) or set(raw) - {"ref", "header", "scheme"} or "ref" not in raw:
        raise _fail(where, "'authorization' is a secret ref, or {\"ref\", \"header\"?, "
                    "\"scheme\"?}")
    ref, header, scheme = raw["ref"], raw.get("header", "Authorization"), raw.get("scheme")
    if not isinstance(ref, str) or not _SECRET_REF.match(ref):
        raise _fail(where, "'authorization.ref' is a secret ref")
    if not isinstance(header, str) or not _HEADER_NAME.match(header) \
            or header.lower() in _FRAMING_HEADERS:
        raise _fail(where, f"'authorization.header' {header!r} is not a header a "
                    f"credential may be sent in")
    if scheme is not None and (not isinstance(scheme, str) or not _AUTH_SCHEME.match(scheme)):
        raise _fail(where, "'authorization.scheme' is one word, e.g. Bearer")
    return {"ref": ref, "header": header, "scheme": scheme}


def _compile_secrets(where: str, raw: Any) -> dict[str, dict]:
    """{"env": {"NAME": {"value": ref} | {"file": ref}}}: how a secret reaches
    a local process. Values become an environment variable of the child and
    nothing else; files become a 0600 temp file the variable points at."""
    if raw is None:
        return {}
    if not isinstance(raw, dict) or set(raw) - {"env"}:
        raise _fail(where, "'secrets' takes only an 'env' object")
    env = raw.get("env", {})
    if not isinstance(env, dict):
        raise _fail(where, "'secrets.env' must be an object")
    out: dict[str, dict] = {}
    for var, how in env.items():
        vw = f"{where}.env.{var}"
        if not _ENV_NAME.match(var):
            raise _fail(vw, "environment variable names are upper-case identifiers")
        if not isinstance(how, dict) or len(how) != 1 or next(iter(how)) not in ("value", "file"):
            raise _fail(vw, "must be {\"value\": ref} or {\"file\": ref}")
        mode, ref = next(iter(how.items()))
        if not isinstance(ref, str) or not _SECRET_REF.match(ref):
            raise _fail(vw, "secret refs are lower-case dotted names")
        out[var] = {"as": mode, "ref": ref}
    return out


_ROLE_ARN = re.compile(r"^arn:aws(-[a-z]+)?:iam::\d{12}:role/[\w+=,.@/-]{1,512}\Z")
_AWS_ACTION = re.compile(r"^[a-z0-9-]{1,32}:[A-Za-z0-9*]{1,128}\Z")
_AWS_RESOURCE = re.compile(r"^arn:aws(-[a-z]+)?:[a-z0-9-]{1,32}:[a-z0-9-]{0,32}:\d{0,12}:[\w+=,.@/:*{}-]{1,1024}\Z")


def _compile_aws(where: str, raw: Any, fields: dict[str, DeclaredField]) -> set[str]:
    """{"role_arn", "actions", "resources", "conditions"?}: what Tower's AWS
    stage asks STS for, per operation. Resources and condition values may
    carry placeholders - exactly one, whole, as everywhere else - filled from
    the request, so the session is scoped to this bucket and this prefix
    and not to the role's whole reach. Returns the fields used."""
    if not isinstance(raw, dict):
        raise _fail(where, "'aws' is an object")
    unknown = set(raw) - {"role_arn", "actions", "resources", "conditions"}
    if unknown:
        raise _fail(where, f"unknown aws keys {sorted(unknown)}")
    arn = _expect_str(where, raw, "role_arn")
    if not _ROLE_ARN.match(arn):
        raise _fail(where, f"role_arn {arn!r} is not an IAM role ARN")
    actions = raw.get("actions")
    if (not isinstance(actions, list) or not actions
            or not all(isinstance(a, str) and _AWS_ACTION.match(a) for a in actions)):
        raise _fail(where, "'actions' is a non-empty list like [\"s3:ListBucket\"]")
    if any(a.endswith(":*") or a == "*" for a in actions):
        raise _fail(where, "an action wildcard is the role's whole reach; name the actions")
    used: set[str] = set()

    def check_value(v: Any, label: str) -> None:
        if not isinstance(v, str):
            raise _fail(where, f"{label} must be a string")
        name = _placeholder(v) if v.startswith("{") and v.endswith("}") else None
        if name is not None:
            if name not in fields or fields[name].type != "string":
                raise _fail(where, f"{label}: placeholder must name a string field")
            used.add(name)
            return
        if "{" in v or "}" in v:
            # a placeholder inside an ARN is the composition the grammar forbids
            # everywhere else - except here, where an ARN has structure the
            # placeholder must sit inside. Permit exactly one, and only in the
            # resource part after the last colon.
            pre, _, tail = v.rpartition(":")
            m = re.fullmatch(r"([\w/+=,.@*-]*)\{([a-z][a-z0-9_]{0,31})\}([\w/+=,.@*-]*)", tail)
            if m is None or "{" in pre:
                raise _fail(where, f"{label}: one placeholder, in the resource part only")
            fname = m.group(2)
            if fname not in fields or fields[fname].type != "string":
                raise _fail(where, f"{label}: placeholder names no string field")
            used.add(fname)

    resources = raw.get("resources")
    if not isinstance(resources, list) or not resources:
        raise _fail(where, "'resources' is a non-empty list of ARNs")
    for r in resources:
        check_value(r, "resources")
        if isinstance(r, str) and not _AWS_RESOURCE.match(r):
            raise _fail(where, f"resource {r!r} is not an ARN")
        # A resource of `*`, or an ARN whose resource part is only a
        # wildcard, is the role's whole reach again - the thing a session
        # policy exists to narrow. Found by the red team, not by design.
        # verified-by: tests/test_taper.py::TestDeclared::test_an_aws_resource_wildcard_is_refused_at_load
        tail = r.rpartition(":")[2] if isinstance(r, str) else ""
        if r == "*" or tail.strip("*/") == "":
            raise _fail(where, f"resource {r!r} is a wildcard; name the resource, "
                        f"with the request's field in it")
    conditions = raw.get("conditions")
    if conditions is not None:
        if not isinstance(conditions, dict):
            raise _fail(where, "'conditions' is an IAM condition block")
        for op, block in conditions.items():
            if not isinstance(block, dict):
                raise _fail(where, f"condition {op!r} is an object of key: value")
            for key, val in block.items():
                if isinstance(val, list):
                    for item in val:
                        check_value(item, f"conditions.{op}.{key}")
                else:
                    check_value(val, f"conditions.{op}.{key}")
    return used


def _compile_layer2(where: str, raw: Any) -> Layer2 | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise _fail(where, "'layer2' is an object with 'enforced_by' and 'check', or null")
    unknown = set(raw) - {"enforced_by", "check"}
    if unknown:
        raise _fail(where, f"unknown layer2 keys {sorted(unknown)}")
    enforced_by = _expect_str(where + ".layer2", raw, "enforced_by")
    check = _expect_str(where + ".layer2", raw, "check")
    if not enforced_by.strip() or not check.strip():
        raise _fail(where, "'layer2.enforced_by' and 'layer2.check' must say something")
    return Layer2(enforced_by.strip(), check.strip())


_TOP_KEYS = {
    "process": {"argv", "secrets", "aws"},
    "ssh": {"host", "program", "args"},
    "sql": {"database", "statement", "params", "writes", "tables", "max_rows", "dsn"},
    "http": {"method", "host", "path", "query", "body", "authorization"},
}
_COMMON_KEYS = {"operation", "summary", "kind", "fields", "layer2"}


def compile_spec(spec: dict, source: str = "<spec>") -> Declaration:
    """Turn a loaded JSON object into a Declaration, or raise SpecError."""
    where = source
    if not isinstance(spec, dict):
        raise _fail(where, "a declaration is a JSON object")
    name = _expect_str(where, spec, "operation")
    if not _NAME.match(name):
        raise _fail(where, f"operation name {name!r}: two lower-case segments, one "
                    f"dot, no underscore in the first (e.g. kubectl.get)")
    where = f"{source} ({name})"
    if name in ops.BUILTIN:
        raise _fail(where, "shadows a built-in operation")
    summary = _expect_str(where, spec, "summary")
    kind = _expect_str(where, spec, "kind")
    if kind not in KINDS:
        raise _fail(where, f"kind must be one of {', '.join(KINDS)}")
    unknown = set(spec) - _COMMON_KEYS - _TOP_KEYS[kind]
    if unknown:
        raise _fail(where, f"unknown keys for kind {kind!r}: {sorted(unknown)}")
    if "layer2" not in spec:
        raise _fail(where, "'layer2' is required: name what enforces this on the "
                    "target, or write null to mark it layer 1 only")
    fields = _compile_fields(where, spec.get("fields"))
    layer2 = _compile_layer2(where, spec.get("layer2"))
    decl = Declaration(name, summary, kind, fields, spec, layer2, source)

    used: set[str] = set()
    if kind == "process":
        tpl = _compile_template(where + ".argv", spec.get("argv"), fields, True)
        used = {v for k, v in tpl if k == "field"}
        _compile_secrets(where + ".secrets", spec.get("secrets"))
        if spec.get("aws") is not None:
            used |= _compile_aws(where + ".aws", spec["aws"], fields)
    elif kind == "ssh":
        host = _expect_str(where, spec, "host")
        h = _placeholder(host)
        if h is not None:
            if h not in fields or fields[h].type != "string":
                raise _fail(where, "'host' placeholder must name a string field")
            used.add(h)
        elif not ops._hostname(host):
            raise _fail(where, f"'host' literal {host!r} is not a hostname")
        program = _expect_str(where, spec, "program")
        if _placeholder(program) is not None:
            raise _fail(where, "'program' is a literal, never a field")
        if not SAFE_VALUE.match(program) or program.rsplit("/", 1)[-1] in INTERPRETERS:
            raise _fail(where, f"'program' {program!r} is refused (interpreter, wrapper, "
                        f"or outside the safe alphabet)")
        tpl = _compile_template(where + ".args", spec.get("args", ["--"]) or ["--"],
                                fields, False)
        used |= {v for k, v in tpl if k == "field"}
    elif kind == "sql":
        db = _expect_str(where, spec, "database")
        d = _placeholder(db)
        if d is not None:
            if d not in fields or fields[d].type != "string":
                raise _fail(where, "'database' placeholder must name a string field")
            used.add(d)
        elif not ops._IDENT.match(db):
            raise _fail(where, f"'database' literal {db!r} is not an identifier")
        statement = _expect_str(where, spec, "statement")
        if "{" in statement or "}" in statement:
            raise _fail(where, "'statement' is fixed text; fields are bound through "
                        "'params', never written into the statement")
        if ";" in statement.rstrip(";").strip() or not statement.strip():
            raise _fail(where, "'statement' is one statement")
        params = spec.get("params", [])
        if not isinstance(params, list) or not all(isinstance(p, str) for p in params):
            raise _fail(where, "'params' is a list of field names, in $1.. order")
        for p in params:
            if p not in fields:
                raise _fail(where, f"params names no field: {p!r}")
        used |= set(params)
        n_markers = len(set(re.findall(r"\$(\d+)", statement)))
        if n_markers != len(params):
            raise _fail(where, f"statement has {n_markers} distinct $n markers and "
                        f"'params' names {len(params)} fields")
        writes = spec.get("writes", False)
        if not isinstance(writes, bool):
            raise _fail(where, "'writes' is true or false")
        tables = spec.get("tables", [])
        if (not isinstance(tables, list) or not tables
                or not all(isinstance(t, str) and _TABLE.match(t) for t in tables)):
            raise _fail(where, "'tables' lists every schema-qualified table the "
                        "statement touches, so policy and the invariants probe "
                        "can see them")
        if "max_rows" in spec and (isinstance(spec["max_rows"], bool)
                                   or not isinstance(spec["max_rows"], int)
                                   or spec["max_rows"] < 1):
            raise _fail(where, "'max_rows' is a positive integer")
        dsn = spec.get("dsn", "pg.dsn")
        if not isinstance(dsn, str) or not _SECRET_REF.match(dsn):
            raise _fail(where, "'dsn' is a secret ref")
    elif kind == "http":
        method = _expect_str(where, spec, "method")
        if method not in HTTP_METHODS:
            raise _fail(where, f"'method' is a literal, one of {', '.join(HTTP_METHODS)}")
        host = _expect_str(where, spec, "host")
        h = _placeholder(host)
        if h is not None:
            if h not in fields or fields[h].type != "string":
                raise _fail(where, "'host' placeholder must name a string field")
            used.add(h)
        elif not ops._hostname(host):
            raise _fail(where, f"'host' literal {host!r} is not a hostname")
        path = spec.get("path")
        if not isinstance(path, list) or not path:
            raise _fail(where, "'path' is a list of segments, each a literal or one field")
        for i, seg in enumerate(path):
            try:
                pn = _placeholder(seg)
            except SpecError as exc:
                raise _fail(f"{where}.path[{i}]", str(exc)) from None
            if pn is None:
                if not SAFE_VALUE.match(seg) or "/" in seg or seg in ("..", "."):
                    raise _fail(f"{where}.path[{i}]", f"segment {seg!r}: one segment, "
                                f"safe alphabet, no slash")
            else:
                if pn not in fields:
                    raise _fail(f"{where}.path[{i}]", f"placeholder names no field: {pn!r}")
                if fields[pn].type == "text":
                    raise _fail(f"{where}.path[{i}]", _TEXT_PLACED)
                used.add(pn)
        if spec.get("query") is not None:
            _compile_query(where + ".query", spec["query"], fields, used)
        body = spec.get("body")
        if body is not None:
            if method in ("GET", "HEAD"):
                raise _fail(where, f"a {method} request carries no body")
            if isinstance(body, str):
                # The original form: the body is one string field, whole.
                b = _placeholder(body)
                if b is None or b not in fields or fields[b].type != "string":
                    raise _fail(where, "'body', if a string, is one string field: "
                                "\"{field}\"; use {\"text\": \"{field}\"} for free text "
                                "or {\"json\": ...} for a structure")
                used.add(b)
            elif isinstance(body, dict) and set(body) == {"text"}:
                b = _placeholder(body["text"]) if isinstance(body["text"], str) else None
                if b is None or b not in fields or fields[b].type not in ("string", "text") \
                        or not fields[b].required:
                    raise _fail(where, "'body.text' is one required string or text field")
                used.add(b)
            elif isinstance(body, dict) and set(body) == {"json"}:
                _compile_json_body(where + ".body.json", body["json"], fields, used)
            else:
                raise _fail(where, "'body' is \"{field}\", {\"text\": \"{field}\"} or "
                            "{\"json\": <template>}")
        _compile_authorization(where + ".authorization", spec.get("authorization"))

    unused = set(fields) - used
    if unused:
        # A field the plan never uses is a field that exists only to be
        # constrained - which is fine - or a field that does nothing and
        # confuses the grant. Say so; do not refuse.
        decl.warnings.append(f"{name}: fields {sorted(unused)} appear in no template; "
                             f"they constrain nothing the operation does")
    if layer2 is None:
        decl.warnings.append(f"{name}: layer 1 only - nothing on the target refuses "
                             f"this on its own. The broker is the only thing saying no.")
    return decl


# ---------------------------------------------------------------- the adapter

class DeclaredAdapter(Adapter):
    """The one adapter class every declaration compiles to.

    derive() returns every field; plan() substitutes each field into exactly
    one slot. There is no string assembly anywhere in this class.
    verified-by: tests/test_taper.py::TestDeclared::test_each_field_lands_in_exactly_one_argv_element
    """

    def __init__(self, decl: Declaration, ssh_adapter=None, http_adapter=None):
        self.decl = decl
        self.operation = decl.name
        self.definition_hash = decl.definition_hash()
        self._ssh = ssh_adapter
        self._http = http_adapter

    def declared_secret_refs(self) -> set[str]:
        s = self.decl.spec
        if self.decl.kind == "process":
            return {v["ref"] for v in _compile_secrets("", s.get("secrets")).values()}
        if self.decl.kind == "ssh":
            return self._ssh.declared_secret_refs() if self._ssh else set()
        if self.decl.kind == "sql":
            return {s.get("dsn", "pg.dsn")}
        if self.decl.kind == "http":
            auth = _compile_authorization("", s.get("authorization"))
            return {auth["ref"]} if auth else set()
        return set()

    def derive(self, request: dict) -> dict[str, Any]:
        # Text fields are content, not attributes: see policy_attributes().
        text = self.decl.text_fields()
        return {name: request[name] for name in self.decl.fields
                if name in request and name not in text}

    # -- substitution -------------------------------------------------------

    @staticmethod
    def _fill(template: list, request: dict) -> list[str]:
        out: list[str] = []
        for element in template:
            name = _placeholder(element)
            if name is None:
                out.append(element)
            elif name in request:
                out.append(str(request[name]))
            # an absent optional field contributes nothing
        return out

    @staticmethod
    def _fill_aws(block: dict, request: dict) -> dict:
        """The aws block with this request's values in place of its
        placeholders. Whole-value placeholders and the one-inside-an-ARN
        form the compiler admitted; nothing else is substituted."""
        def one(v):
            if not isinstance(v, str):
                return v
            if v.startswith("{") and v.endswith("}") and "{" not in v[1:]:
                return str(request[v[1:-1]])
            def sub(m):
                return str(request[m.group(1)])
            return re.sub(r"\{([a-z][a-z0-9_]{0,31})\}", sub, v)
        out = {"role_arn": block["role_arn"], "actions": list(block["actions"]),
               "resources": [one(r) for r in block["resources"]]}
        if block.get("conditions"):
            out["conditions"] = {
                op: {k: ([one(i) for i in v] if isinstance(v, list) else one(v))
                     for k, v in blk.items()}
                for op, blk in block["conditions"].items()}
        return out

    @staticmethod
    def _one(value: str, request: dict) -> str:
        name = _placeholder(value)
        return value if name is None else str(request[name])

    @staticmethod
    def _segment(value: str, request: dict) -> str:
        """One path segment. A field fills exactly one: a value carrying a
        slash, a percent sign or a dot-segment would be normalized into a
        different path on the way out - `%2e%2e` decodes to `..` - so it is
        refused here rather than resolved there.
        verified-by: tests/test_taper.py::TestHttpDeclared::test_a_path_field_fills_exactly_one_segment
        """
        name = _placeholder(value)
        if name is None:
            return value
        filled = str(request[name])
        if not one_segment(filled):
            raise OperationError(f"path field {name!r} must be one segment: no slash, "
                                 f"percent-escape or dot-segment")
        return filled

    @staticmethod
    def _json(template: Any, request: dict, fields: dict) -> Any:
        if isinstance(template, dict):
            out = {}
            for k, v in template.items():
                m = _PLACEHOLDER.match(v) if isinstance(v, str) else None
                if m and m.group(1) not in request:
                    continue                      # an absent optional member is omitted
                out[k] = DeclaredAdapter._json(v, request, fields)
            return out
        if isinstance(template, list):
            return [DeclaredAdapter._json(v, request, fields) for v in template]
        if isinstance(template, str):
            m = _PLACEHOLDER.match(template)
            if m:
                return request[m.group(1)]        # json.dumps does the quoting
        return template

    def plan(self, request: dict, grant: dict) -> ExecPlan:
        s = self.decl.spec
        kind = self.decl.kind
        base_detail = {
            "declared": self.decl.name,
            "definition": self.definition_hash,
            "layer2": None if self.decl.layer2 is None else self.decl.layer2.enforced_by,
        }
        if kind == "process":
            argv = self._fill(s["argv"], request)
            inject = _compile_secrets("", s.get("secrets"))
            detail = {**base_detail, "inject": inject,
                      "boundary": "local process; " + (
                          self.decl.layer2.enforced_by if self.decl.layer2
                          else "layer 1 only")}
            if s.get("aws") is not None:
                detail["aws"] = self._fill_aws(s["aws"], request)
            return ExecPlan(
                kind="process", argv=argv,
                secret_refs={var: how["ref"] for var, how in inject.items()},
                detail=detail,
            )
        if kind == "ssh":
            if self._ssh is None:
                raise OperationError(f"{self.decl.name}: no ssh adapter configured")
            inner = {"host": self._one(s["host"], request), "program": s["program"],
                     "args": self._fill(s.get("args", []), request)}
            plan = self._ssh.plan(inner, grant)
            plan.detail.update(base_detail)
            return plan
        if kind == "sql":
            from .adapters.postgres import invariants_probe
            writes = bool(s.get("writes", False))
            params = [request[p] for p in s.get("params", [])]
            detail = {
                **base_detail,
                "database": self._one(s["database"], request),
                "statement_kind": "declared-write" if writes else "declared-read",
                "tables": list(s["tables"]),
                "max_rows": s.get("max_rows"),
                "statement_text": s["statement"],
                "statement_params": params,
                # Declared statements number their markers ($1, $2), which
                # psycopg's default cursor does not read; the executor binds
                # them through a raw cursor. Without this every declared
                # statement with a parameter failed against a real server.
                "param_style": "numeric",
                "session_settings": {
                    "statement_timeout": "15000ms",
                    "idle_in_transaction_session_timeout": "5s",
                    "default_transaction_read_only": "off" if writes else "on",
                    "row_security": "on",
                },
                "boundary": "postgres:role+grant+force-rls",
            }
            if writes:
                detail["invariants"] = invariants_probe(
                    [tuple(t.split(".", 1)) for t in s["tables"]], grant)
            return ExecPlan(kind="sql", secret_refs={"dsn": s.get("dsn", "pg.dsn")},
                            detail=detail)
        if kind == "http":
            if self._http is None:
                raise OperationError(f"{self.decl.name}: no http adapter configured")
            path = "/" + "/".join(self._segment(seg, request) for seg in s["path"])
            inner = {"method": s["method"], "host": self._one(s["host"], request),
                     "path": path}
            body = s.get("body")
            content_type = None
            if isinstance(body, str):
                body_field = _placeholder(body)
                if body_field in request:
                    inner["body"] = request[body_field]
            elif isinstance(body, dict) and "text" in body:
                inner["body"] = str(request[_placeholder(body["text"])])
                content_type = "text/plain; charset=utf-8"
            elif isinstance(body, dict) and "json" in body:
                inner["body"] = json.dumps(self._json(body["json"], request, self.decl.fields),
                                           ensure_ascii=False, separators=(",", ":"))
                content_type = "application/json"
            plan = self._http.plan(inner, grant)
            if s.get("query") is not None:
                # After normalization, never through it: the path is resolved
                # and policy-checked, then the encoded query is appended. A
                # value is encoded whole, so `&`, `=` and `#` in it are data.
                from urllib.parse import quote
                pairs = []
                for key, value in _compile_query("", s["query"], self.decl.fields, set()):
                    name = _placeholder(value)
                    if name is not None and name not in request:
                        continue                  # an absent optional field sends nothing
                    filled = value if name is None else str(request[name])
                    pairs.append(f"{quote(key, safe='')}={quote(filled, safe='')}")
                if pairs:
                    plan.detail["url"] += "?" + "&".join(pairs)
            auth = _compile_authorization("", s.get("authorization"))
            if auth is not None:
                plan.secret_refs["authorization"] = auth["ref"]
                plan.detail["auth_header"] = auth["header"]
                if auth["scheme"]:
                    plan.detail["auth_scheme"] = auth["scheme"]
            if "body" in inner:
                plan.detail["body"] = inner["body"]
            if content_type:
                plan.detail["content_type"] = content_type
            plan.detail.update(base_detail)
            return plan
        raise OperationError(f"{self.decl.name}: unknown kind {kind!r}")


# ------------------------------------------------------------------- catalog

@dataclass
class Catalog:
    declarations: dict[str, Declaration] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def hashes(self) -> dict[str, str]:
        return {n: d.definition_hash() for n, d in self.declarations.items()}

    def adapters(self, ssh_adapter=None, http_adapter=None) -> dict[str, Adapter]:
        return {n: DeclaredAdapter(d, ssh_adapter, http_adapter)
                for n, d in self.declarations.items()}

    def register(self) -> None:
        """Make every declaration a first-class operation: the registry, the
        policy attributes, and (for the MCP server) a tool schema."""
        for d in self.declarations.values():
            ops.REGISTRY[d.name] = d.operation()
            ops.POLICY_ATTRIBUTES[d.name] = d.policy_attributes()
            ops.DECLARED_SCHEMAS[d.name] = d.json_schema()


def load_file(path: Path) -> Declaration:
    raw = path.read_bytes()
    if len(raw) > MAX_SPEC_BYTES:
        raise SpecError(f"{path}: larger than {MAX_SPEC_BYTES} bytes")
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SpecError(f"{path}: not JSON ({exc})") from None
    return compile_spec(spec, str(path))


def load_dir(directory: Path) -> Catalog:
    """Every *.json in the directory, sorted. A bad file is an error for that
    file and does not stop the others from loading; the CLI decides whether
    an error is fatal (it is, for the broker)."""
    catalog = Catalog()
    if not directory.is_dir():
        return catalog
    for path in sorted(directory.glob("*.json")):
        try:
            decl = load_file(path)
        except SpecError as exc:
            catalog.errors.append(str(exc))
            continue
        if decl.name in catalog.declarations:
            catalog.errors.append(f"{path}: {decl.name} is already declared by "
                                  f"{catalog.declarations[decl.name].source}")
            continue
        catalog.declarations[decl.name] = decl
        catalog.warnings.extend(decl.warnings)
    return catalog
