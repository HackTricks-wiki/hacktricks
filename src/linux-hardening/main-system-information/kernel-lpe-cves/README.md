# Матеріали про kernel, LPE та CVE

{{#include ../../../banners/hacktricks-training.md}}

У цих тематичних дослідженнях розглянуто різні примітиви локального підвищення привілеїв. Перш ніж застосовувати техніку, перевірте в кожній статті вразливий продукт або kernel, конфігурацію та необхідні передумови. Для ширшого переліку способів перерахування хоста скористайтеся [чеклістом підвищення привілеїв у Linux](../linux-privilege-escalation-checklist.md).

Для Dirty Pipe (CVE-2022-0847) в [оригінальному дослідженні](https://dirtypipe.cm4all.com/) зазначено upstream-виправлення для stable-версій 5.10.102, 5.15.25 і 5.16.11. Версія kernel зі старішого вразливого діапазону — лише підказка для перевірки: дистрибутиви можуть переносити виправлення в інші випуски, а для примітиву запису в page cache цільовий файл має бути доступним для читання. Перезапис доступного для читання виконуваного файла SUID — один із можливих шляхів отримання привілеїв, якщо перехід set-ID залишається ефективним; зміна `/etc/passwd` із подальшою автентифікацією також може залежати від локального стека PAM. Перш ніж оцінювати можливість експлуатації, перевірте встановлений пакет kernel від постачальника, запущений kernel після перезавантаження, дозволи цільового файла, параметр монтування `nosuid` і `no_new_privs`. Не виконуйте пробний запис під час пасивного перерахування. Див. [статус для конкретних випусків Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Виявлення служби VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): виконання з підвищеними привілеями через пошук шляху до процесу в недовіреному середовищі.
- [Перезапис page cache через AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): шлях перезапису page cache у kernel.
- [TOCTOU у POSIX CPU timers, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race condition в обробці таймерів.
- [Гонка під час завершення процесу в Linux ptrace і викрадення файлових дескрипторів через `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): доступ до дескрипторів під час гонки, пов’язаної із завершенням процесу.

## Дотичні тематичні дослідження з Binary Exploitation

У розділі Binary Exploitation докладніше розглянуто примітиви експлуатації, розташування пам’яті та обходи механізмів захисту для цих цілей у Linux kernel:

- [Use-after-free SKB із позасмуговими даними AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): вразливість сокета перетворено на примітиви читання та запису в kernel.
- [Underflow scatterlist через конкурентний записувач AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): race condition у записувачі skcipher перетворено на запис у kernel.
- [Use-after-free у Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): примітив запису вказівника розширено за допомогою буферів pipe і workqueue.
- [Запис за межами буфера в потоках ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): експлуатація heap у kernel та обходи механізмів захисту.
- [TOCTOU у POSIX CPU timers, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): розгляд гонки таймерів з погляду Binary Exploitation, також стисло описаний вище.
- [Обхід KASLR для статичної лінійної карти Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): виявлення адрес для експлуатації kernel на arm64.
- [Обхід привілеїв GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): шлях через GPU Android для доступу до пам’яті kernel.
- [Use-after-free через тайм-аут завдання Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): вразливість Android-прискорювача, використана для запису в kernel.
{{#include ../../../banners/hacktricks-training.md}}
