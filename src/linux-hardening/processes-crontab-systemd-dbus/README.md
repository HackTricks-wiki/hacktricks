# 进程、Crontab、Systemd 和 D-Bus

{{#include ../../banners/hacktricks-training.md}}

计划任务和进程间通信可以使用不同于调用者的权限执行代码。测试服务或任务之前，请检查其所有者、命令和可写输入。

- [进程枚举和服务路径](process-enumeration-and-service-paths.md)介绍进程树、运行时文件和 systemd 执行链。
- [Cron 任务和 systemd 定时器](cron-and-systemd-timers.md)介绍计划任务的发现和可写输入。
- [D-Bus 枚举和命令注入权限提升](d-bus-enumeration-and-command-injection-privilege-escalation.md)介绍消息总线和特权服务方法。
- [要执行的 Payload](payloads-to-execute.md)汇总了在确定执行路径后可使用的 payload。

如需更全面地检查 cron 任务和 systemd 服务，请使用 [Linux 权限提升检查清单](../main-system-information/linux-privilege-escalation-checklist.md)。
{{#include ../../banners/hacktricks-training.md}}
