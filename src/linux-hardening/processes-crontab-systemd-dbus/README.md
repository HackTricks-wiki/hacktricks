# Процеси, Crontab, Systemd і D-Bus

{{#include ../../banners/hacktricks-training.md}}

Заплановані завдання та міжпроцесна взаємодія можуть запускати код із привілеями, відмінними від привілеїв ініціатора. Перш ніж тестувати службу чи завдання, перевірте власника, команду та параметри, доступні для запису.

- [Перелік процесів і шляхи служб](process-enumeration-and-service-paths.md) описує дерева процесів, файли середовища виконання та ланцюжки запуску systemd.
- [Завдання Cron і таймери systemd](cron-and-systemd-timers.md) описує пошук запланованих завдань і параметрів, доступних для запису.
- [Перелік D-Bus і підвищення привілеїв через ін’єкцію команд](d-bus-enumeration-and-command-injection-privilege-escalation.md) описує шину повідомлень і методи привілейованих служб.
- [Payloads для виконання](payloads-to-execute.md) містить payloads, які можна використовувати після виявлення шляху виконання.

Для ширшого аналізу завдань Cron і служб systemd скористайтеся [контрольним списком підвищення привілеїв у Linux](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
