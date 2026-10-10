# Основи Linux

{{#include ../../banners/hacktricks-training.md}}

Це відправна точка для оцінювання Linux-хостів. На цих сторінках описано широкий робочий процес підвищення привілеїв, практичні команди, змінні середовища та поширені обмеження, що впливають на те, що можна запустити на хості.

- [Підвищення привілеїв у Linux](linux-privilege-escalation/README.md) описує процес перерахування та потенційні шляхи локального підвищення привілеїв. Для коротшого списку завдань скористайтеся [контрольним списком підвищення привілеїв](../main-system-information/linux-privilege-escalation-checklist.md).
- [Запуск оболонки, aliases та історія команд](shell-startup-aliases-and-history.md) пояснює розв’язання команд, виконання файлів запуску та підказки в історії команд.
- [Корисні команди Linux](useful-linux-commands.md) містить команди для перевірки файлів, процесів, служб і середовища.
- [Змінні середовища Linux](linux-environment-variables.md) пояснює, як значення середовища впливають на виконання та де можуть з’являтися конфіденційні значення.
- [Обхід обмежень Linux](bypass-linux-restrictions/README.md) охоплює обмежені оболонки та середовища виконання, зокрема захист файлової системи, `noexec` і distroless-системи.

## Експлуатація нативних бінарних файлів

Якщо під час оцінювання виявлено вразливий виконуваний файл Linux, скористайтеся відповідними матеріалами в розділі Binary Exploitation:

- [Формат ELF і поведінка завантажувача](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) та [захист бінарних файлів і способи його обходу](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) пояснюють структуру виконуваних файлів і механізми пом’якшення експлуатації.
- [Експлуатація стека](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) і [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) охоплюють атаки на потік керування.
- [Експлуатація купи Libc](../../binary-exploitation/libc-heap/README.md) і [форматні рядки](../../binary-exploitation/format-strings/README.md) охоплюють інші поширені способи використання пошкодження пам’яті.

Приклади, пов’язані з ядром, наведено в матеріалах [Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
