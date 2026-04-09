# container-defense-stack

Container and Kubernetes security toolkit providing Dockerfile hardening guides, secure workload manifests, RBAC baselines, network policies, and manifest validators for DevSecOps teams.

## Objective

Provide production-ready, reusable security baselines for containerized workloads — reducing misconfigurations that lead to privilege escalation, lateral movement, or data exposure in Kubernetes clusters.

## Problem Solved

Teams frequently deploy containers with excessive privileges, missing resource limits, and no network segmentation. This toolkit provides validated templates, validators, and documentation to establish security-by-default.

## Use Cases

- Hardening Dockerfiles for Python, Node.js, and Go applications
- Applying security context to Kubernetes workloads
- Implementing RBAC with minimum privilege
- Segmenting namespaces with network policies
- Validating manifests before deployment
- Training teams on container security fundamentals

## Ethical Disclaimer

All content is defensive. Use validators and baselines on infrastructure you own or are authorized to assess. Do not use this toolkit to exploit container environments.

## Structure

```
docker/             — Secure Dockerfile examples
kubernetes/         — Secure manifest templates
validators/         — Manifest and Dockerfile validators
policies/           — Reusable security policies
docs/               — Hardening guides and architecture
training/           — Tutorials and labs
```

## How to Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Validate a Kubernetes manifest
k1n-container-guard validate-manifest --path deployment.yaml

# Validate a Dockerfile
k1n-container-guard validate-dockerfile --path Dockerfile
```

If you are working in an offline or PEP 668-managed environment, create the
virtualenv with `python3 -m venv --system-site-packages .venv` and install with
`pip install -e . --no-deps --no-build-isolation` to reuse the locally available
Python packages.

## License

MIT — see [LICENSE](LICENSE).
