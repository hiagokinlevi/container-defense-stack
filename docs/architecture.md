# Validator Architecture

This document describes the design of the two security validators in this
repository: `manifest_validator` for Kubernetes YAML manifests and
`dockerfile_validator` for Dockerfiles.

---

## Overview

Both validators follow the same pattern:

```
Input file
    |
    v
Parser (yaml.safe_load_all / line-by-line)
    |
    v
Rule checks (pure functions, each returns findings)
    |
    v
List[Finding]  — structured, serialisable result objects
    |
    v
CLI layer (Click + Rich table)
```

No network calls, no subprocess invocations, no cluster access — the validators
are purely static analysis tools that run offline.

---

## YAML Parsing (manifest_validator)

`validate_manifest(path)` opens the file and feeds it through `yaml.safe_load_all`,
which returns a generator of Python dicts — one per YAML document. This supports
multi-document files (documents separated by `---`).

`safe_load_all` is used instead of `load_all` to prevent arbitrary code execution
via YAML tags (`!!python/object/apply:`). This is essential because the input is
untrusted manifest content.

---

## Rule Checks

### Manifest rules

All checks live in `_check_workload(doc, findings)`. The function:

1. Extracts the container list via `_get_containers(doc)`, which handles the
   structural difference between `Deployment`, `Job`, `CronJob`, and raw `Pod`
   manifests.
2. Iterates over each container and inspects the `securityContext` and `resources`
   keys.
3. Appends a `ManifestFinding` to `findings` for each policy violation.
4. Performs one pod-level check: `automountServiceAccountToken`.

Each check is an explicit `if` statement with a direct dict key lookup — no
schema library or external rule engine. This keeps the logic readable and keeps
dependencies minimal.

### Dockerfile rules

`validate_dockerfile(path)` reads the file as plain text and processes it
line-by-line. It tracks two boolean accumulators (`has_user`, `has_healthcheck`)
that are checked after the loop for file-level findings.

Per-line checks use:
- `str.upper().startswith(...)` for instruction-type matching (case-insensitive,
  consistent with Docker's parser behaviour).
- A single `re.match` for the `ENV` secret detection rule — required because the
  pattern depends on the variable name, not just the instruction keyword.

---

## Finding Data Model

### ManifestFinding

```python
@dataclass
class ManifestFinding:
    rule_id: str       # e.g. "SEC001" — stable identifier for suppression lists.
    severity: Severity # CRITICAL | HIGH | MEDIUM | LOW | INFO
    message: str       # Human-readable description of the violation.
    path: str          # Dot-notation path to the offending field in the manifest.
    remediation: str   # Concrete fix instruction.
```

### DockerFinding

```python
@dataclass
class DockerFinding:
    rule_id: str       # e.g. "DF001"
    severity: Severity # HIGH | MEDIUM | LOW
    line: int          # 1-based line number (0 = file-level finding).
    message: str
    remediation: str
```

Both use `@dataclass` for zero-boilerplate construction, equality comparison, and
repr. The `Severity` enums inherit from `str` so they serialise naturally to JSON
without a custom encoder.

---

## CLI Interface

`cli/main.py` uses Click for argument parsing and Rich for terminal output.

```
cli validate-manifest  PATH
cli validate-dockerfile PATH
```

Both commands:
1. Call the appropriate validator function.
2. Render findings in a `rich.table.Table` with colour-coded severity cells.
3. Exit with code `1` if any HIGH or CRITICAL finding is present, so CI
   pipelines fail automatically on serious violations.
4. Exit with code `0` if no findings or only LOW/MEDIUM findings.

The CLI is intentionally thin — it contains no business logic, only presentation
and exit-code logic. This makes the validators easy to use as a library without
importing Click or Rich.

---

## Extending the Validators

### Adding a manifest rule

1. Add a new `rule_id` constant (e.g., `SEC009`).
2. Add an `if` block inside `_check_workload` (or a new helper if the check is
   complex) that appends a `ManifestFinding` when the condition is met.
3. Add a test in `tests/test_manifest_validator.py` that asserts the new rule ID
   appears when the misconfiguration is present.

### Adding a Dockerfile rule

1. Add a new `rule_id` constant (e.g., `DF006`).
2. Add the check inside the `for i, line in enumerate(lines)` loop, or as a
   post-loop check for file-level properties.
3. Add a test in `tests/test_dockerfile_validator.py`.

### Severity conventions

| Severity | Meaning |
|---|---|
| CRITICAL | Immediate exploitation risk; blocks deployment in CI |
| HIGH | Significant risk; blocks deployment in CI |
| MEDIUM | Important but non-blocking; should be resolved before next release |
| LOW | Minor improvement; track in backlog |
| INFO | Informational only; no action required |
