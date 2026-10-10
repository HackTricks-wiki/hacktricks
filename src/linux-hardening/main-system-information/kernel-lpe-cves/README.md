# Матеріали про Kernel, LPE і CVE

{{#include ../../../banners/hacktricks-training.md}}

Ці приклади охоплюють різні примітиви локального підвищення привілеїв. Перш ніж застосовувати техніку, перевірте у відповідній статті, який продукт або kernel уражено, а також потрібні конфігурацію та передумови. Для ширшого переліку перевірок хоста скористайтеся [контрольним списком підвищення привілеїв у Linux](../linux-privilege-escalation-checklist.md).

Для Dirty Pipe (CVE-2022-0847) в [оригінальному дослідженні](https://dirtypipe.cm4all.com/) зазначено виправлення в upstream stable у версіях 5.10.102, 5.15.25 і 5.16.11. Версія kernel зі старішого вразливого діапазону — це лише привід для перевірки: дистрибутиви можуть переносити виправлення в пакети з іншими назвами версій, а цільовий файл має бути доступним для читання, щоб спрацював примітив запису в page cache. Перезапис доступного для читання виконуваного файла SUID — один із можливих шляхів підвищення привілеїв, якщо його перехід set-ID залишається ефективним; зміна `/etc/passwd` з подальшою автентифікацією також може залежати від локального стека PAM. Перш ніж оцінювати можливість експлуатації, перевірте встановлений пакет kernel від постачальника, запущений kernel після перезавантаження, дозволи на цільовий файл, параметр монтування `nosuid` і `no_new_privs`. Не виконуйте пробний запис під час пасивної розвідки. Див. [статус для конкретних випусків Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Виявлення сервісу VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): виконання з підвищеними привілеями через пошук процесу за недовіреним шляхом.
- [Перезапис page cache через AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): шлях перезапису page cache ядра.
- [Гонка TOCTOU у POSIX CPU timers, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): гонка під час обробки таймерів.
- [Гонка завершення процесу в Linux ptrace і крадіжка файлових дескрипторів через `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): доступ до дескрипторів під час гонки завершення процесу.

## Пов’язані приклади binary exploitation

У розділі Binary Exploitation докладніше розглянуто примітиви експлуатації, компонування пам’яті та обходи засобів захисту для цих цілей у ядрі Linux:

- [Use-after-free SKB для позасмугових даних AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): помилку сокета розвинуто до примітивів читання й запису в ядрі.
- [Use-after-free у Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): примітив запису за вказівником розширено за допомогою pipe buffers і workqueues.
- [Запис за межами буфера в потоках ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): експлуатація heap ядра й обходи засобів захисту.
- [Гонка TOCTOU у POSIX CPU timers, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): опис гонки таймерів у контексті binary exploitation, також стисло розглянутий вище.
- [Обхід KASLR для статичної лінійної мапи Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): виявлення адрес для експлуатації ядра arm64.
- [Обхід привілеїв Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): шлях через GPU Android до доступу до пам’яті ядра.
- [Use-after-free через тайм-аут завдання Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): помилку прискорювача Android використано для запису в ядро.
{{#include ../../../banners/hacktricks-training.md}}
