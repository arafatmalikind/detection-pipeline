from pathlib import Path

import pytest

from detlab import backends
from detlab.__main__ import main
from detlab.match import matches
from detlab.sigma import SigmaError, parse_rule

ROOT = Path(__file__).resolve().parent.parent


def rule(detection, logsource=None):
    return parse_rule({
        "title": "t",
        "id": "00000000-0000-4000-8000-000000000000",
        "level": "low",
        "logsource": logsource or {"product": "windows", "category": "process_creation"},
        "detection": detection,
    })


def test_list_of_values_is_or():
    r = rule({"s": {"Image|endswith": ["\\a.exe", "\\b.exe"]}, "condition": "s"})
    assert matches(r, {"Image": "C:\\B.EXE"})
    assert not matches(r, {"Image": "C:\\c.exe"})


def test_all_modifier():
    r = rule({"s": {"CommandLine|contains|all": ["x", "y"]}, "condition": "s"})
    assert matches(r, {"CommandLine": "..x..y.."})
    assert not matches(r, {"CommandLine": "..x.."})


def test_cased():
    r = rule({"s": {"User|cased": "SYSTEM"}, "condition": "s"})
    assert matches(r, {"User": "SYSTEM"})
    assert not matches(r, {"User": "system"})


def test_null_means_missing_or_empty():
    r = rule({"s": {"ParentImage": None}, "condition": "s"})
    assert matches(r, {})
    assert matches(r, {"ParentImage": ""})
    assert not matches(r, {"ParentImage": "x"})


def test_list_of_maps_is_or():
    r = rule({"s": [{"A": "1"}, {"B": "2"}], "condition": "s"})
    assert matches(r, {"B": "2"})
    assert not matches(r, {"A": "2"})


def test_precedence_and_binds_tighter():
    r = rule({"a": {"X": "1"}, "b": {"Y": "1"}, "c": {"Z": "1"}, "condition": "a or b and c"})
    assert matches(r, {"X": "1"})
    assert not matches(r, {"Y": "1"})


def test_one_of_pattern_and_not():
    r = rule({
        "sel_a": {"X": "1"}, "sel_b": {"Y": "1"}, "filter": {"Z": "1"},
        "condition": "1 of sel_* and not filter",
    })
    assert matches(r, {"Y": "1"})
    assert not matches(r, {"Y": "1", "Z": "1"})


def test_unsupported_modifier_is_rejected():
    with pytest.raises(SigmaError, match="unsupported modifier"):
        rule({"s": {"X|re": "a.*"}, "condition": "s"})


def test_unknown_selection_in_condition():
    with pytest.raises(SigmaError, match="unknown selection"):
        rule({"s": {"X": "1"}, "condition": "s and t"})


def test_spl_or_is_parenthesised():
    r = rule({"a": {"X": "1", "Y": "2"}, "b": {"Z": "3"}, "condition": "a or b"})
    spl = backends.get("spl", ROOT / "mappings").convert(r).splitlines()[0]
    assert spl.endswith('((X="1" Y="2") OR Z="3")')


def test_spl_refuses_literal_asterisk():
    r = rule({"s": {"X": "a*b"}, "condition": "s"})
    with pytest.raises(backends.BackendError):
        backends.get("spl", ROOT / "mappings").convert(r)


def test_kql_int_unquoted():
    r = rule({"s": {"EventID": 7045}, "condition": "s"}, {"product": "windows", "service": "system"})
    assert "EventID == 7045" in backends.get("kql", ROOT / "mappings").convert(r)


def test_unmapped_logsource():
    r = rule({"s": {"X": "1"}, "condition": "s"}, {"product": "linux", "category": "auditd"})
    with pytest.raises(backends.BackendError, match="no mapping"):
        backends.get("kql", ROOT / "mappings").convert(r)


@pytest.mark.parametrize("cmd", [["lint"], ["test"], ["convert", "spl"], ["convert", "kql"]])
def test_repo_rules_pass(cmd, capsys):
    assert main(cmd) == 0
