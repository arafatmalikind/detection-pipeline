"""A deliberately small Sigma reader.

Supports the parts of the spec I actually use in this repo:
  - selections as a map (AND across fields) or a list of maps (OR)
  - value lists (OR, or AND with |all)
  - modifiers: contains, startswith, endswith, all, cased
  - null values (field must be absent or empty)
  - conditions with and / or / not / parentheses / "1 of x*" / "all of x*"

Anything else raises SigmaError rather than being silently ignored, so a rule
never converts to something weaker than what was written.
"""

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "all", "cased"}


class SigmaError(ValueError):
    pass


@dataclass
class FieldTest:
    field: str
    values: list          # list of str/int/None
    op: str = "eq"        # eq, contains, startswith, endswith
    all: bool = False
    cased: bool = False


@dataclass
class Selection:
    # outer list = OR of alternatives, inner list = AND of field tests
    alternatives: list


@dataclass
class Rule:
    path: Path
    title: str
    id: str
    level: str
    status: str
    logsource: dict
    tags: list
    selections: dict
    condition: object      # parsed AST
    raw: dict = field(repr=False, default_factory=dict)

    @property
    def name(self):
        return self.path.stem


# --- selections ---------------------------------------------------------

def _field_test(key, value):
    parts = key.split("|")
    name, mods = parts[0], parts[1:]
    unknown = set(mods) - KNOWN_MODIFIERS
    if unknown:
        raise SigmaError(f"unsupported modifier(s) {sorted(unknown)} on {name}")
    ops = [m for m in mods if m in ("contains", "startswith", "endswith")]
    if len(ops) > 1:
        raise SigmaError(f"{name}: only one of contains/startswith/endswith allowed")
    values = value if isinstance(value, list) else [value]
    for v in values:
        if isinstance(v, (dict, list)):
            raise SigmaError(f"{name}: nested values are not supported")
    return FieldTest(
        field=name,
        values=values,
        op=ops[0] if ops else "eq",
        all="all" in mods,
        cased="cased" in mods,
    )


def _selection(name, body):
    if isinstance(body, dict):
        return Selection([[_field_test(k, v) for k, v in body.items()]])
    if isinstance(body, list) and all(isinstance(x, dict) for x in body):
        return Selection([[_field_test(k, v) for k, v in alt.items()] for alt in body])
    raise SigmaError(f"selection {name}: keyword lists are not supported, use a field")


# --- condition parser -----------------------------------------------------

TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokens(text):
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise SigmaError(f"cannot parse condition near: {text[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _Parser:
    # or_expr  := and_expr ("or" and_expr)*
    # and_expr := not_expr ("and" not_expr)*
    # not_expr := "not" not_expr | atom
    # atom     := "(" or_expr ")" | ("1"|"all") "of" pattern | name

    def __init__(self, tokens, names):
        self.t = tokens
        self.i = 0
        self.names = names

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expect=None):
        tok = self.peek()
        if tok is None or (expect and tok.lower() != expect):
            raise SigmaError(f"expected {expect or 'token'}, got {tok}")
        self.i += 1
        return tok

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise SigmaError(f"unexpected token {self.peek()}")
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.peek() and self.peek().lower() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.not_expr()
        while self.peek() and self.peek().lower() == "and":
            self.take()
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self):
        if self.peek() and self.peek().lower() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok == "(":
            self.take()
            node = self.or_expr()
            self.take(")")
            return node
        if tok and tok.lower() in ("1", "all") and self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take("of")
            pattern = self.take()
            if pattern == "them":
                matched = sorted(self.names)
            else:
                matched = sorted(n for n in self.names if fnmatch.fnmatchcase(n, pattern))
            if not matched:
                raise SigmaError(f"'{quant} of {pattern}' matches no selection")
            op = "or" if quant == "1" else "and"
            node = ("sel", matched[0])
            for n in matched[1:]:
                node = (op, node, ("sel", n))
            return node
        name = self.take()
        if name not in self.names:
            raise SigmaError(f"condition references unknown selection {name}")
        return ("sel", name)


# --- loading -------------------------------------------------------------

def parse_rule(data, path=Path("<memory>")):
    for key in ("title", "id", "logsource", "detection", "level"):
        if key not in data:
            raise SigmaError(f"{path.name}: missing '{key}'")
    det = dict(data["detection"])
    cond = det.pop("condition", None)
    if not isinstance(cond, str):
        raise SigmaError(f"{path.name}: detection.condition must be a single string")
    det.pop("timeframe", None)
    selections = {name: _selection(name, body) for name, body in det.items()}
    try:
        ast = _Parser(_tokens(cond), set(selections)).parse()
    except SigmaError as e:
        raise SigmaError(f"{path.name}: {e}") from None
    return Rule(
        path=path,
        title=data["title"],
        id=str(data["id"]),
        level=data["level"],
        status=data.get("status", "experimental"),
        logsource=data["logsource"],
        tags=list(data.get("tags", [])),
        selections=selections,
        condition=ast,
        raw=data,
    )


def load_rule(path):
    path = Path(path)
    with path.open(encoding="utf-8") as fh:
        return parse_rule(yaml.safe_load(fh), path)


def load_dir(directory):
    return [load_rule(p) for p in sorted(Path(directory).rglob("*.yml"))]
