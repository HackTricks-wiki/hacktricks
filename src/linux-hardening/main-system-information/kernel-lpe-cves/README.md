# Матеріали про kernel, LPE та CVE

{{#include ../../../banners/hacktricks-training.md}}

У цих прикладах розглянуто різні примітиви локального підвищення привілеїв. Перш ніж застосовувати техніку, перевірте в кожній статті вразливий продукт або kernel, конфігурацію та необхідні передумови. Для ширшого збору інформації про хост скористайтеся [контрольним списком підвищення привілеїв у Linux](../linux-privilege-escalation-checklist.md).

Для Dirty Pipe (CVE-2022-0847) в [оригінальному дослідженні](https://dirtypipe.cm4all.com/) зазначено, що виправлення для upstream stable з’явилися у версіях 5.10.102, 5.15.25 і 5.16.11. Версія kernel зі старішого вразливого діапазону — лише підстава для подальшої перевірки: дистрибутиви можуть переносити виправлення в старіші версії під іншими назвами, а для примітива запису в page cache цільовий файл має бути доступним для читання. Перезапис доступного для читання виконуваного файла SUID — один із можливих шляхів підвищення привілеїв, якщо перехід set-ID залишається ефективним; зміна `/etc/passwd` з подальшою автентифікацією також може залежати від локального стека PAM. Перш ніж оцінювати можливість експлуатації, перевірте встановлений пакет kernel від постачальника, kernel, який запущено після перезавантаження, дозволи цільового файла, параметр монтування `nosuid` і `no_new_privs`. Не запускайте пробний запис під час пасивного збору інформації. Див. [статус для конкретних випусків Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Виявлення служби VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): виконання з підвищеними привілеями через виявлення шляху до процесу з недовірених джерел.
- [Перезапис page cache через AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): шлях до перезапису page cache у kernel.
- [Перегони TOCTOU у POSIX CPU timers та експлуатація, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): завершення та видалення таймера під час виходу задачі, зокрема передумови для IRQ-шляху та дослідження експлуатації.
- [Перегони під час завершення процесу в Linux ptrace та викрадення дескриптора файла через `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): доступ до дескриптора під час перегонів, пов’язаних із завершенням процесу.

## Дотичні приклади бінарної експлуатації

У розділі «Бінарна експлуатація» докладніше розглянуто примітиви експлуатації, розташування в пам’яті та обходи засобів захисту для цих цілей Linux kernel:

- [Use-after-free SKB у AF_UNIX out-of-band](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): помилка сокета, розвинена до примітивів читання та запису в kernel.
- [Underflow scatterlist у конкурентному writer AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): перегони під час запису skcipher, розвинені до запису в kernel.
- [Use-after-free у Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): примітив запису через вказівник, розширений за допомогою pipe buffers і workqueues.
- [Запис поза межами в streams ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): експлуатація heap kernel та обходи засобів захисту.
- [Обхід KASLR у статичній лінійній мапі Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): визначення адрес для експлуатації kernel на arm64.
- [Обхід привілеїв GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): шлях через GPU Android до доступу до пам’яті kernel.
- [Use-after-free через тайм-аут завдання Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): помилка прискорювача Android, використана для запису в kernel.
{{#include ../../../banners/hacktricks-training.md}}
