# Основи Linux

{{#include ../../banners/hacktricks-training.md}}

Це відправна точка для оцінювання Linux-хоста. На цих сторінках описано широкий процес підвищення привілеїв, практичні команди, змінні середовища та поширені обмеження, які впливають на те, що можна запускати на хості.

- [Підвищення привілеїв у Linux](linux-privilege-escalation/README.md) описує збір інформації та потенційні шляхи локального підвищення привілеїв. Для коротшого списку завдань скористайтеся [контрольним списком підвищення привілеїв](../main-system-information/linux-privilege-escalation-checklist.md).
- [Запуск оболонки, псевдоніми та історія команд](shell-startup-aliases-and-history.md) пояснює пошук команд, виконання файлів запуску та підказки в історії команд.
- [Корисні команди Linux](useful-linux-commands.md) містить команди для перевірки файлів, процесів, служб і середовища.
- [Змінні середовища Linux](linux-environment-variables.md) пояснює, як значення середовища впливають на виконання та де можуть з’являтися чутливі значення.
- [Обхід обмежень Linux](bypass-linux-restrictions/README.md) охоплює обмежені оболонки й середовища виконання, зокрема захист файлової системи, `noexec` і distroless-системи.

## Експлуатація нативних бінарних файлів

Якщо під час оцінювання виявлено вразливий виконуваний файл Linux, скористайтеся відповідними матеріалами з Binary Exploitation:

- [Формат ELF і поведінка завантажувача](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) та [захисти бінарних файлів і способи їх обходу](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) пояснюють структуру виконуваних файлів і механізми захисту.
- [Експлуатація стека](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) і [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) описують атаки на потік керування.
- [Експлуатація купи libc](../../binary-exploitation/libc-heap/README.md) і [рядки форматування](../../binary-exploitation/format-strings/README.md) охоплюють інші поширені способи використання пошкодження пам’яті.

Матеріали з конкретними прикладами для ядра наведено в розділі [Матеріали про Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
