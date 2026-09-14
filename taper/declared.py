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
    type: str                     # "string" | "integer"
    required: bool
    pattern: re.Pattern | None
    enum: frozenset | None
    lo: int | None
    hi: int | None
    describe: str

    def accepts(self, value: Any) -> bool:
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
        d: dict[str, Any] = {"type": self.type}
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

    def operation(self) -> Operation:
        return Operation(
            name=self.name,
            summary=self.summary,
            fields=tuple(
                Field(f.name, str if f.type == "string" else int,
                      required=f.required, validator=f.accepts, describe=f.describe)
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
        return tuple(self.fields)

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
        unknown = set(fd) - {"type", "required", "pattern", "enum", "min", "max", "describe"}
        if unknown:
            raise _fail(fw, f"unknown keys {sorted(unknown)}")
        ftype = _expect_str(fw, fd, "type")
        if ftype not in ("string", "integer"):
            raise _fail(fw, "type must be 'string' or 'integer'")
        required = fd.get("required", True)
        if not isinstance(required, bool):
            raise _fail(fw, "'required' must be true or false")
        describe = _expect_str(fw, fd, "describe", required=False) or ""
        pattern = enum = lo = hi = None
        if ftype == "string":
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
        out[name] = DeclaredField(name, ftype, required, pattern, enum, lo, hi, describe)
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
    "process": {"argv", "secrets"},
    "ssh": {"host", "program", "args"},
    "sql": {"database", "statement", "params", "writes", "tables", "max_rows", "dsn"},
    "http": {"method", "host", "path", "body", "authorization"},
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
                used.add(pn)
        body = spec.get("body")
        if body is not None:
            b = _placeholder(body) if isinstance(body, str) else None
            if b is None or b not in fields or fields[b].type != "string":
                raise _fail(where, "'body', if present, is one string field: \"{field}\"")
            used.add(b)
        auth = spec.get("authorization")
        if auth is not None and (not isinstance(auth, str) or not _SECRET_REF.match(auth)):
            raise _fail(where, "'authorization' is a secret ref")

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
            return {s["authorization"]} if s.get("authorization") else set()
        return set()

    def derive(self, request: dict) -> dict[str, Any]:
        return {name: request[name] for name in self.decl.fields if name in request}

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
    def _one(value: str, request: dict) -> str:
        name = _placeholder(value)
        return value if name is None else str(request[name])

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
            return ExecPlan(
                kind="process", argv=argv,
                secret_refs={var: how["ref"] for var, how in inject.items()},
                detail={**base_detail, "inject": inject,
                        "boundary": "local process; " + (
                            self.decl.layer2.enforced_by if self.decl.layer2
                            else "layer 1 only")},
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
            path = "/" + "/".join(self._one(seg, request) for seg in s["path"])
            inner = {"method": s["method"], "host": self._one(s["host"], request),
                     "path": path}
            body_field = _placeholder(s["body"]) if s.get("body") else None
            if body_field and body_field in request:
                inner["body"] = request[body_field]
            plan = self._http.plan(inner, grant)
            if s.get("authorization"):
                plan.secret_refs["authorization"] = s["authorization"]
            if "body" in inner:
                plan.detail["body"] = inner["body"]
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
