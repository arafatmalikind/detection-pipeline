# detection-pipeline

Detection rules written once in Sigma format, tested against sample events, and converted to Splunk SPL and Microsoft Sentinel KQL in CI.

Most SOCs I have seen manage correlation searches by editing them directly in the SIEM. That works until someone changes a field name, a "quick tuning" silently kills a rule, or the same detection has to exist in two platforms. This repo is the workflow I prefer instead: rules live in Git, every rule ships with events that must and must not trigger it, and nothing merges unless the tests pass.

```
rules/*.yml  ──lint──►  test against tests/events/*.yml  ──convert──►  queries/spl, queries/kql
```

## Layout

```
rules/          Sigma rules, grouped by source (windows, cloud, ot)
tests/events/   one file per rule: events under match: and no_match:
mappings/       logsource and field mappings per backend
queries/        generated SPL and KQL (committed, checked in CI)
detlab/         the parser, matcher, linter and converters
```

## Rules

| Rule | Source | ATT&CK | Level |
|---|---|---|---|
| Office application spawns a script interpreter | Sysmon / MDE | T1566.001, T1059 | high |
| LSASS memory dump through comsvcs.dll | Sysmon / MDE | T1003.001 | critical |
| Volume shadow copies deleted | Sysmon / MDE | T1490 | high |
| Service installed from a user-writable path | Windows System 7045 | T1543.003 | medium |
| Successful sign-in using legacy authentication | Entra ID sign-in logs | T1078.004 | medium |
| Modbus write from a non-engineering host | Zeek modbus.log | ICS T0855, T0836 | high |

The Modbus rule is the one I find most useful in OT environments. Function code writes from anything other than the engineering workstations or HMIs are rare enough that the alert volume stays near zero, and when it fires it matters.

## Usage

```bash
pip install -r requirements.txt pytest
make check                       # unit tests + lint + rule tests
python -m detlab convert spl     # print SPL for every rule
python -m detlab convert kql -o queries
```

Example output:

~~~
``` Volume shadow copies deleted [c022fe77-0c73-43c3-9fbb-d2ab44bc02a1] ```
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (((Image="*\\vssadmin.exe" ...
~~~

## Writing a rule

1. Add `rules/<area>/<name>.yml`. It needs a UUID, author, date, description, false positives and at least one ATT&CK technique tag, or lint fails.
2. Add `tests/events/<name>.yml` with at least one `match` event. Add `no_match` events for the near misses you expect in production, these are what stop a later tuning change from making the rule too broad.
3. `make check && make queries`, commit both the rule and the regenerated queries.

## Why not pySigma?

pySigma is the right choice for a large rule base. I wanted something small enough to read in one sitting and strict about what it accepts: unsupported modifiers, keyword searches and unknown logsources fail loudly instead of converting to something weaker than the rule says. The supported subset is listed at the top of `detlab/sigma.py`.

Two things worth knowing about the converters:

- SPL evaluates `OR` before the implicit `AND`, so `a b OR c` means `a AND (b OR c)`. The SPL backend parenthesises every compound expression rather than relying on precedence. There is a unit test for this because it is an easy bug to ship.
- The Sentinel mapping for Windows System events uses the `Event` table with `RenderedDescription`. If you collect 7045 through a DCR into a parsed table, change `mappings/sentinel.yml` and nothing else.

## License

MIT. See [LICENSE](LICENSE).
