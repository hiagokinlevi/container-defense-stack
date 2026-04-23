# CI Policy Validation Example (Fail Pipeline on Findings)

Use `k1n-container-guard` in CI as a **blocking security gate** for Kubernetes manifests and Dockerfiles.

## 1) Local command examples

```bash
# Fail if manifest issues are found
k1n-container-guard validate-manifest kubernetes/deployment.yaml

# Fail if Dockerfile issues are found
k1n-container-guard validate-dockerfile docker/Dockerfile
```

## 2) Exit-code behavior for CI

`k1n-container-guard` follows standard CLI behavior:

- `0` = validation passed (no blocking findings)
- non-zero (typically `1`) = validation failed (findings or execution error)

In CI systems, any non-zero exit code should fail the job automatically.

## 3) Minimal copy-paste CI snippet (shell)

Use this in any CI runner step:

```bash
set -euo pipefail

k1n-container-guard validate-manifest kubernetes/deployment.yaml
k1n-container-guard validate-dockerfile docker/Dockerfile

echo "Security validation passed"
```

Because `set -e` is enabled, the pipeline stops immediately if either command returns non-zero.

## 4) Optional: validate multiple files

```bash
set -euo pipefail

for f in kubernetes/*.yaml; do
  k1n-container-guard validate-manifest "$f"
done

for d in Dockerfile docker/*.Dockerfile; do
  [ -f "$d" ] && k1n-container-guard validate-dockerfile "$d"
done
```

This pattern is useful when hardening monorepos or multi-service projects.
