import re
import uuid

LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"stable", "test", "experimental", "deprecated"}
TAG = re.compile(r"^attack\.([a-z_]+(\.[a-z_]+)?|t\d{4}(\.\d{3})?)$")


def lint(rule):
    problems = []
    raw = rule.raw

    try:
        if str(uuid.UUID(rule.id)) != rule.id:
            problems.append("id is not a lowercase UUID")
    except ValueError:
        problems.append("id is not a UUID")

    if rule.level not in LEVELS:
        problems.append(f"level '{rule.level}' is not one of {sorted(LEVELS)}")
    if rule.status not in STATUSES:
        problems.append(f"status '{rule.status}' is not one of {sorted(STATUSES)}")

    for key in ("description", "author", "date", "falsepositives"):
        if not raw.get(key):
            problems.append(f"missing {key}")

    if not any(t.startswith("attack.t") for t in rule.tags):
        problems.append("no ATT&CK technique tag")
    for t in rule.tags:
        if not TAG.match(t):
            problems.append(f"tag '{t}' does not look like an ATT&CK tag")

    if len(rule.title) > 80:
        problems.append("title longer than 80 characters")

    return problems


def duplicate_ids(rules):
    seen, dupes = {}, []
    for r in rules:
        if r.id in seen:
            dupes.append(f"{r.name}: id also used by {seen[r.id]}")
        seen[r.id] = r.name
    return dupes
