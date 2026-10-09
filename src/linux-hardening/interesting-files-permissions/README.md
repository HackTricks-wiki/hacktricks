# Interesting Files and Permissions

{{#include ../../banners/hacktricks-training.md}}

File ownership, write access, mount options, and executable privileges can change a local user's effective reach. Begin by identifying the target file or execution path, then use the relevant page:

- [SUID, SGID, ACLs, and sensitive files](suid-sgid-and-acl-triage.md) gives a starting workflow for executable privileges and hidden access grants.
- [Arbitrary file write to root](write-to-root.md) describes how writes to privileged paths can be turned into escalation.
- [Linux capabilities](linux-capabilities.md) explains per-process and per-file capabilities.
- [SUID shared library and linker abuse](suid-shared-library-and-linker-abuse.md) covers dynamic loading around privileged binaries.
- [`ld.so` privilege escalation example](ld.so.conf-example.md) follows a linker configuration case.
- [NFS `no_root_squash` and `no_all_squash` misconfiguration](nfs-no_root_squash-misconfiguration-pe.md) covers remote filesystem identity mapping.
- [Wildcard spare tricks](wildcards-spare-tricks.md) covers argument expansion in privileged commands.
- [SELinux](selinux.md) explains policy enforcement and relevant investigation steps.
{{#include ../../banners/hacktricks-training.md}}
