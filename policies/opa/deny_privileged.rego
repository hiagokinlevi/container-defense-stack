package kubernetes.admission

# OPA/Gatekeeper admission policy — deny privileged containers.
#
# Blocks any Pod (or workload creating Pods) that sets
# securityContext.privileged: true on any container or initContainer.
#
# Enforcement: Deny at admission time.
# Severity: CRITICAL — privileged containers have full host kernel access.

deny[msg] {
    # Match all workloads that produce Pods
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "CRITICAL [SEC001]: Container '%v' requests privileged mode. Remove securityContext.privileged or set it to false.",
        [container.name],
    )
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.initContainers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "CRITICAL [SEC001]: initContainer '%v' requests privileged mode. Remove securityContext.privileged or set it to false.",
        [container.name],
    )
}
