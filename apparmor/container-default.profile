#include <tunables/global>

profile container-default flags=(attach_disconnected,mediate_deleted) {
  # Basic capability policy: deny dangerous privilege-escalation capabilities.
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_ptrace,
  deny capability sys_time,
  deny capability sys_rawio,
  deny capability sys_boot,
  deny capability mac_admin,
  deny capability mac_override,
  deny capability mknod,
  deny capability audit_control,
  deny capability setfcap,
  deny capability net_admin,
  deny capability net_raw,

  # Block mounting and privileged kernel interfaces.
  deny mount,
  deny umount,
  deny pivot_root,
  deny /sys/** wklx,
  deny /proc/sys/** wklx,
  deny /proc/sysrq-trigger rwklx,
  deny /proc/kcore rwklx,
  deny /proc/kallsyms rwklx,

  # Allow read-only access to common runtime paths.
  / r,
  /** r,

  # Allow executing binaries and shared libs in standard locations.
  /bin/** ix,
  /sbin/** ix,
  /usr/bin/** ix,
  /usr/sbin/** ix,
  /usr/local/bin/** ix,
  /lib/** mr,
  /lib64/** mr,
  /usr/lib/** mr,
  /usr/lib64/** mr,

  # Permit writes only to standard ephemeral temp locations.
  /tmp/** rw,
  /var/tmp/** rw,
  /dev/shm/** rw,

  # Allow limited device/runtime interactions expected in containers.
  /dev/null rw,
  /dev/zero rw,
  /dev/random r,
  /dev/urandom r,
  /dev/tty rw,

  # Allow process and network metadata reads.
  /proc/** r,
  /etc/hosts r,
  /etc/hostname r,
  /etc/resolv.conf r,

  # Deny writes to broad filesystem locations by default.
  deny /** w,
  deny /etc/** w,
  deny /usr/** w,
  deny /bin/** w,
  deny /sbin/** w,
  deny /lib/** w,
  deny /lib64/** w,
  deny /var/** w,

  # Allow signal and unix mediation defaults needed by many runtimes.
  signal,
  unix,
}
