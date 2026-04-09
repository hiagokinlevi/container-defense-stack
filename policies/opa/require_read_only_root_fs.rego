package kubernetes.admission

# OPA/Gatekeeper admission policy — require read-only root filesystem.
#
# A writable root filesystem allows attackers who gain code execution inside
# a container to modify system binaries, drop persistence, or tamper with
# configuration files. Enforcing readOnlyRootFilesystem limits blast radius.
#
# For writable paths (temp files, logs, caches), use emptyDir volumes.
#
# Enforcement: Deny at admission time.
# Severity: MEDIUM

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf(
        "MEDIUM [SEC003]: Container '%v' has a writable root filesystem. Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for writable paths.",
        [container.name],
    )
}
