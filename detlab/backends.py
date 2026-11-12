"""Turn a parsed rule into SPL or KQL.

Field names and the search prefix / table come from mappings/*.yml so the
rules stay vendor neutral. A logsource that has no mapping is an error, not a
guess.
"""

from pathlib import Path

import yaml


class BackendError(ValueError):
    pass


def _logsource_key(ls):
    return ":".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k))


class Backend:
    name = ""

    def __init__(self, mapping_file):
        with Path(mapping_file).open(encoding="utf-8") as fh:
            self.mapping = yaml.safe_load(fh)

    def source(self, rule):
        key = _logsource_key(rule.logsource)
        src = self.mapping.get("logsources", {}).get(key)
        if src is None:
            raise BackendError(f"{self.name}: no mapping for logsource '{key}' ({rule.name})")
        return src

    def field(self, rule, name):
        src = self.source(rule)
        return src.get("fields", {}).get(name, self.mapping.get("fields", {}).get(name, name))

    def node(self, node, rule):
        kind = node[0]
        if kind == "sel":
            return self.selection(rule.selections[node[1]], rule)
        if kind == "not":
            return f"NOT {self.wrap(self.node(node[1], rule))}" if self.name == "spl" \
                else f"not({self.node(node[1], rule)})"
        joiner = {"and": self.AND, "or": self.OR}[kind]
        return f"{self.wrap(self.node(node[1], rule))}{joiner}{self.wrap(self.node(node[2], rule))}"

    @staticmethod
    def wrap(s):
        # Parenthesise anything compound. SPL in particular binds OR tighter
        # than the implicit AND, so relying on precedence is not safe.
        if " " not in s:
            return s
        if s.startswith("(") and s.endswith(")"):
            depth = 0
            for i, ch in enumerate(s):
                depth += ch == "("
                depth -= ch == ")"
                if depth == 0 and i < len(s) - 1:
                    break
            else:
                return s
        return f"({s})"

    def selection(self, sel, rule):
        alts = []
        for alt in sel.alternatives:
            parts = [self.test(t, rule) for t in alt]
            alts.append(self.AND.join(self.wrap(p) for p in parts))
        if len(alts) == 1:
            return alts[0]
        return self.OR.join(self.wrap(a) for a in alts)


class SplBackend(Backend):
    name = "spl"
    AND = " "
    OR = " OR "

    @staticmethod
    def quote(v):
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'

    def test(self, t, rule):
        f = self.field(rule, t.field)
        if t.cased:
            raise BackendError(f"spl: |cased is not supported in search syntax ({rule.name})")
        parts = []
        for v in t.values:
            if v is None:
                parts.append(f"NOT {f}=*")
                continue
            s = str(v)
            if "*" in s:
                # Splunk has no reliable way to search a literal asterisk
                raise BackendError(f"spl: literal '*' in value for {t.field} ({rule.name})")
            if t.op == "contains":
                s = f"*{s}*"
            elif t.op == "startswith":
                s = f"{s}*"
            elif t.op == "endswith":
                s = f"*{s}"
            parts.append(f"{f}={self.quote(s)}")
        return (self.AND if t.all else self.OR).join(parts)

    def convert(self, rule):
        src = self.source(rule)
        body = self.wrap(self.node(rule.condition, rule))
        out = f"{src['prefix']} {body}".strip()
        if src.get("suffix"):
            out += f"\n{src['suffix']}"
        return out


class KqlBackend(Backend):
    name = "kql"
    AND = " and "
    OR = " or "

    @staticmethod
    def quote(v):
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'

    def test(self, t, rule):
        f = self.field(rule, t.field)
        nulls = [v for v in t.values if v is None]
        vals = [v for v in t.values if v is not None]
        parts = [f"isempty({f})" for _ in nulls]
        cs = "_cs" if t.cased else ""

        nums = [v for v in vals if isinstance(v, int) and not isinstance(v, bool)]
        if nums and t.op == "eq":
            # integers stay unquoted so they compare against int columns
            parts += [f"{f} == {v}" for v in nums]
            vals = [v for v in vals if v not in nums]

        if not vals:
            pass
        elif t.op == "eq" and len(vals) > 1 and not t.all:
            op = "in" if t.cased else "in~"
            parts.append(f"{f} {op} ({', '.join(self.quote(v) for v in vals)})")
        else:
            for v in vals:
                if t.op == "eq":
                    parts.append(f"{f} {'==' if t.cased else '=~'} {self.quote(v)}")
                else:
                    parts.append(f"{f} {t.op}{cs} {self.quote(v)}")
        return (self.AND if t.all else self.OR).join(parts)

    def convert(self, rule):
        src = self.source(rule)
        lines = [src["table"], f"| where {self.node(rule.condition, rule)}"]
        if src.get("suffix"):
            lines.append(src["suffix"])
        return "\n".join(lines)


def get(name, mappings_dir):
    mappings_dir = Path(mappings_dir)
    if name == "spl":
        return SplBackend(mappings_dir / "splunk.yml")
    if name == "kql":
        return KqlBackend(mappings_dir / "sentinel.yml")
    raise BackendError(f"unknown backend {name}")
