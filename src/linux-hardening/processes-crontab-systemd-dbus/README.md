# 进程、Crontab、Systemd 和 D-Bus

{{#include ../../banners/hacktricks-training.md}}

计划任务和进程间通信可以启动权限与调用者不同的代码。在进行测试前，请检查服务或任务的所有者、命令以及可写入的输入。

- [进程枚举和服务路径](process-enumeration-and-service-paths.md)介绍进程树、运行时文件和 systemd 执行链。
- [Cron 任务和 systemd 定时器](cron-and-systemd-timers.md)介绍计划任务的发现和可写入的输入。
- [D-Bus 枚举和命令注入权限提升](d-bus-enumeration-and-command-injection-privilege-escalation.md)介绍消息总线和特权服务方法。
- [用于执行的 Payloads](payloads-to-execute.md)汇集了在确定执行路径后可使用的 Payloads。

若要全面检查 cron 任务和 systemd 服务，请使用 [Linux 权限提升检查清单](../main-system-information/linux-privilege-escalation-checklist.md)。
{{#include ../../banners/hacktricks-training.md}}
