# Processes, Crontab, Systemd, और D-Bus

{{#include ../../banners/hacktricks-training.md}}

शेड्यूल किए गए जॉब और interprocess communication, कॉलर से अलग privileges के साथ code चला सकते हैं। किसी service या job को test करने से पहले उसके owner, command और writable inputs की जाँच करें।

- [Process enumeration और service paths](process-enumeration-and-service-paths.md) में process trees, runtime files और systemd execution chains शामिल हैं।
- [Cron jobs और systemd timers](cron-and-systemd-timers.md) में scheduled-task discovery और writable inputs शामिल हैं।
- [D-Bus enumeration और command injection privilege escalation](d-bus-enumeration-and-command-injection-privilege-escalation.md) में message bus और privileged service methods शामिल हैं।
- [चलाने के लिए payloads](payloads-to-execute.md) में ऐसे payloads संकलित हैं जिनका उपयोग execution path की पहचान होने पर किया जा सकता है।

Cron jobs और systemd services की व्यापक समीक्षा के लिए, [Linux privilege escalation checklist](../main-system-information/linux-privilege-escalation-checklist.md) का उपयोग करें।
{{#include ../../banners/hacktricks-training.md}}
