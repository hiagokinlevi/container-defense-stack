package kubernetes.admission

# OPA/Gatekeeper admission policy — require non-root execution.
#
# Blocks Pods that do not set runAsNonRoot: true at the container level.
# Containers running as UID 0 (root) can escape into the host if the
# container runtime is misconfigured or if a kernel vulnerability is exploited.
#
# Enforcement: Deny at admission time.
# Severity: HIGH

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]

    # Check: runAsNonRoot must be explicitly true (missing = implicitly false)
    not container.securityContext.runAsNonRoot == true

    # Also deny if runAsUser is explicitly 0 (root), even when runAsNonRoot is set
    msg := sprintf(
        "HIGH [SEC004]: Container '%v' does not enforce non-root execution. Set securityContext.runAsNonRoot: true.",
        [container.name],
    )
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]

    # Explicitly running as root UID 0 is always denied, regardless of runAsNonRoot
    container.securityContext.runAsUser == 0

    msg := sprintf(
        "HIGH [SEC004]: Container '%v' explicitly runs as UID 0 (root). Choose a non-zero runAsUser.",
        [container.name],
    )
}
