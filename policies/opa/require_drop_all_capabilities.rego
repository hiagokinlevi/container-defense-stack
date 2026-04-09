package kubernetes.admission

# OPA/Gatekeeper admission policy — require dropping all Linux capabilities.
#
# Linux capabilities grant fine-grained superuser privileges to processes.
# Containers should start with no capabilities and only add back what is
# explicitly required (allowlist model). Retaining default capabilities like
# NET_RAW, SYS_CHROOT, or AUDIT_WRITE expands the attack surface.
#
# Enforcement: Deny at admission time.
# Severity: MEDIUM

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]

    # capabilities.drop must include "ALL"
    dropped := {cap | cap := container.securityContext.capabilities.drop[_]}
    not "ALL" in dropped

    msg := sprintf(
        "MEDIUM [SEC005]: Container '%v' does not drop all capabilities. Add 'ALL' to securityContext.capabilities.drop and only add back what is explicitly needed.",
        [container.name],
    )
}
