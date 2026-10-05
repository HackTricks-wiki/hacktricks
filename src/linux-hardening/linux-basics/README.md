# Linux Basics

{{#include ../../banners/hacktricks-training.md}}

This is the starting point for Linux host assessment. The pages cover a broad privilege escalation workflow, practical commands, environment variables, and common restrictions that affect what can run on a host.

- [Linux privilege escalation](linux-privilege-escalation/README.md) walks through enumeration and potential local escalation paths. For a shorter task list, use the [privilege escalation checklist](../main-system-information/linux-privilege-escalation-checklist.md).
- [Shell startup, aliases, and history](shell-startup-aliases-and-history.md) explains command resolution, startup-file execution, and history clues.
- [Useful Linux commands](useful-linux-commands.md) collects commands for inspecting files, processes, services, and the environment.
- [Linux environment variables](linux-environment-variables.md) explains how environment values affect execution and where sensitive values can appear.
- [Bypass Linux restrictions](bypass-linux-restrictions/README.md) covers constrained shells and execution environments, including filesystem protections, `noexec`, and distroless systems.

## Native binary exploitation

When an assessment leads to a vulnerable Linux executable, use the relevant material in Binary Exploitation:

- [ELF format and loader behavior](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) and [binary protections and bypasses](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) explain the executable layout and mitigations.
- [Stack exploitation](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) and [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) cover control-flow attacks.
- [Libc heap exploitation](../../binary-exploitation/libc-heap/README.md) and [format strings](../../binary-exploitation/format-strings/README.md) cover other common memory-corruption paths.

Kernel-specific case studies are linked from [Kernel/LPE/CVE material](../main-system-information/kernel-lpe-cves/README.md).
