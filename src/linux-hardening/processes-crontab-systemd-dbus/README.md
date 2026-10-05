# Processes, Crontab, Systemd, and D-Bus

{{#include ../../banners/hacktricks-training.md}}

Scheduled jobs and interprocess communication can launch code with privileges different from those of the caller. Inspect the owner, command, and writable inputs of a service or job before testing it.

- [Process enumeration and service paths](process-enumeration-and-service-paths.md) covers process trees, runtime files, and systemd execution chains.
- [Cron jobs and systemd timers](cron-and-systemd-timers.md) covers scheduled-task discovery and writable inputs.
- [D-Bus enumeration and command injection privilege escalation](d-bus-enumeration-and-command-injection-privilege-escalation.md) covers the message bus and privileged service methods.
- [Payloads to execute](payloads-to-execute.md) collects payloads that can be used when an execution path has been identified.

For a wider review of cron jobs and systemd services, use the [Linux privilege escalation checklist](../main-system-information/linux-privilege-escalation-checklist.md).
