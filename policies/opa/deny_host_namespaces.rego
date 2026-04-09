package kubernetes.admission

# OPA/Gatekeeper admission policy — deny host namespace sharing.
#
# Sharing the host network, PID, or IPC namespace with a container allows
# the container to observe and interact with host-level processes and network
# traffic. This breaks container isolation and is rarely needed in production.
#
# Enforcement: Deny at admission time.
# Severity: CRITICAL (hostPID/hostNetwork), HIGH (hostIPC)

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.hostPID == true
    msg := "CRITICAL [SEC010]: Pod requests hostPID: true. Remove hostPID or set it to false. Host PID namespace sharing allows container processes to see and signal all host processes."
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.hostNetwork == true
    msg := "CRITICAL [SEC011]: Pod requests hostNetwork: true. Remove hostNetwork or set it to false. Host network sharing exposes the node's network interfaces to the container."
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.hostIPC == true
    msg := "HIGH [SEC012]: Pod requests hostIPC: true. Remove hostIPC or set it to false. Host IPC sharing allows the container to access shared memory segments on the host."
}
