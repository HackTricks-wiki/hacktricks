# User Information

{{#include ../../banners/hacktricks-training.md}}

User identity, group membership, and delegated credentials determine which resources a process can reach. Check the effective identity and supplementary groups before investigating the access paths below.

- [Users, sessions, and credential artifacts](user-and-session-triage.md) covers account enumeration, active logins, SSH and shell artifacts, and credential stores.
- [Real, effective, and saved user IDs](euid-ruid-suid.md) explains identity changes around SUID programs and process execution.
- [Interesting groups for Linux privilege escalation](interesting-groups-linux-pe/README.md) covers group-granted access, including LXD/LXC.
- [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) examines risks from forwarded SSH credentials.
- [Linux Active Directory](linux-active-directory.md) covers hosts joined to an AD environment.
{{#include ../../banners/hacktricks-training.md}}
