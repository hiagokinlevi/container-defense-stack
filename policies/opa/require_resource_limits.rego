package kubernetes.admission

# OPA/Gatekeeper admission policy — require CPU and memory limits.
#
# Containers without resource limits can consume unlimited node resources,
# causing noisy-neighbour denial of service against other tenants and making
# resource-exhaustion attacks trivially easy.
#
# Enforcement: Deny at admission time.
# Severity: MEDIUM (memory), LOW (cpu) — memory OOM kills are more dangerous.

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf(
        "MEDIUM [SEC006]: Container '%v' has no memory limit. Set resources.limits.memory to prevent resource exhaustion.",
        [container.name],
    )
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf(
        "LOW [SEC007]: Container '%v' has no CPU limit. Set resources.limits.cpu.",
        [container.name],
    )
}
