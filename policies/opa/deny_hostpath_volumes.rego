package kubernetes.admission

# OPA/Gatekeeper admission policy — deny hostPath volumes.
#
# hostPath volumes let Pods read or write files from the underlying node.
# That breaks workload-to-node isolation and can expose sensitive host state
# such as container runtime sockets, kubelet credentials, or system logs.
#
# Enforcement: Deny at admission time.
# Severity: HIGH

deny[msg] {
    input.request.kind.kind == "Pod"
    volume := input.request.object.spec.volumes[_]
    volume.hostPath
    path := volume.hostPath.path
    msg := sprintf(
        "HIGH [SEC014]: Pod volume '%v' declares hostPath '%v'. Replace hostPath with a safer volume type or isolate the workload and mount only a narrowly scoped read-only path when no alternative exists.",
        [volume.name, path],
    )
}
