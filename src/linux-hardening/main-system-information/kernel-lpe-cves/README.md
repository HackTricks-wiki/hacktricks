# Матеріали про Kernel, LPE та CVE

{{#include ../../../banners/hacktricks-training.md}}

Ці розбори охоплюють різні примітиви локального підвищення привілеїв. Перш ніж застосовувати техніку, перевірте в кожній статті вразливий продукт або ядро, конфігурацію та необхідні передумови. Для ширшого переліку перевірок хоста скористайтеся [чеклістом підвищення привілеїв у Linux](../linux-privilege-escalation-checklist.md).

Щодо Dirty Pipe (CVE-2022-0847), в [оригінальному дослідженні](https://dirtypipe.cm4all.com/) зазначено, що виправлення для upstream stable з’явилися у версіях 5.10.102, 5.15.25 та 5.16.11. Версія ядра зі старішого вразливого діапазону — лише привід для подальшої перевірки: дистрибутиви можуть переносити виправлення до ядер під іншими назвами випусків, а цільовий файл має бути доступним для читання, щоб спрацював примітив запису в page cache. Перезапис доступного для читання SUID-виконуваного файла — один із можливих шляхів підвищення привілеїв, якщо перехід set-ID залишається дієвим; зміна `/etc/passwd` з подальшою автентифікацією також може залежати від локального стека PAM. Перш ніж оцінювати можливість експлуатації, перевірте встановлений пакет ядра від постачальника, запущене після перезавантаження ядро, дозволи цільового файла, параметр монтування `nosuid` і `no_new_privs`. Не виконуйте пробний запис під час пасивної розвідки. Див. [статус для конкретного випуску Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Виявлення служби VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): виконання з підвищеними привілеями через пошук шляху процесу, якому не можна довіряти.
- [Перезапис page cache через AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): шлях перезапису page cache ядра.
- [TOCTOU у таймерах CPU POSIX, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): гонитва під час обробки таймерів.
- [Гонитва завершення Linux ptrace та викрадення файлового дескриптора через `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): доступ до дескриптора під час гонитви завершення процесу.

## Пов’язані розбори експлуатації бінарних файлів

У розділі Binary Exploitation докладніше розглянуто примітиви експлуатації, розташування пам’яті та обходи механізмів захисту для цих цілей у ядрі Linux:

- [Use-after-free SKB позасмугових даних AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): помилку сокета використано для створення примітивів читання та запису в ядрі.
- [Use-after-free Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): примітив запису за вказівником розширено за допомогою pipe buffers і workqueues.
- [Вихід за межі буфера потоків ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): експлуатація купи ядра та обходи механізмів захисту.
- [TOCTOU у таймерах CPU POSIX, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): розбір гонитви таймерів з погляду експлуатації бінарних файлів, також стисло описаної вище.
- [Обхід KASLR для статичної лінійної мапи Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): виявлення адрес для експлуатації ядра arm64.
- [Обхід привілеїв Adreno A7xx GPU/SMMU](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): шлях через GPU Android до доступу до пам’яті ядра.
- [Use-after-free тайм-ауту завдання Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): помилку прискорювача Android використано для запису в ядро.
{{#include ../../../banners/hacktricks-training.md}}
