# Процеси, Crontab, Systemd і D-Bus

{{#include ../../banners/hacktricks-training.md}}

Заплановані завдання та міжпроцесна взаємодія можуть запускати код із правами, відмінними від прав викликувача. Перш ніж тестувати службу чи завдання, перевірте його власника, команду та доступні для запису вхідні дані.

- [Перелік процесів і шляхи служб](process-enumeration-and-service-paths.md) охоплює дерева процесів, файли середовища виконання та ланцюжки запуску systemd.
- [Завдання cron і таймери systemd](cron-and-systemd-timers.md) охоплює пошук запланованих завдань і доступні для запису вхідні дані.
- [Перелік D-Bus і підвищення привілеїв через ін’єкцію команд](d-bus-enumeration-and-command-injection-privilege-escalation.md) охоплює шину повідомлень і методи привілейованих служб.
- [Payloads для виконання](payloads-to-execute.md) містить payloads, які можна використати після виявлення шляху виконання.

Для ширшого аудиту завдань cron і служб systemd скористайтеся [контрольним списком підвищення привілеїв у Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
