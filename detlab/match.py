"""Evaluate a parsed rule against a single event (a flat dict)."""


def _norm(v, cased):
    if v is None:
        return None
    s = str(v)
    return s if cased else s.lower()


def _one(test, event_value, wanted):
    if wanted is None:
        return event_value in (None, "")
    if event_value is None:
        return False
    a = _norm(event_value, test.cased)
    b = _norm(wanted, test.cased)
    if test.op == "contains":
        return b in a
    if test.op == "startswith":
        return a.startswith(b)
    if test.op == "endswith":
        return a.endswith(b)
    return a == b


def field_matches(test, event):
    ev = event.get(test.field)
    hits = (_one(test, ev, w) for w in test.values)
    return all(hits) if test.all else any(hits)


def selection_matches(sel, event):
    return any(all(field_matches(t, event) for t in alt) for alt in sel.alternatives)


def evaluate(node, rule, event):
    kind = node[0]
    if kind == "sel":
        return selection_matches(rule.selections[node[1]], event)
    if kind == "not":
        return not evaluate(node[1], rule, event)
    if kind == "and":
        return evaluate(node[1], rule, event) and evaluate(node[2], rule, event)
    if kind == "or":
        return evaluate(node[1], rule, event) or evaluate(node[2], rule, event)
    raise ValueError(kind)


def matches(rule, event):
    return evaluate(rule.condition, rule, event)
