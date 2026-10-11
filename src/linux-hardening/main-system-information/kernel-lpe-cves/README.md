# Матеріали про ядро, LPE та CVE

{{#include ../../../banners/hacktricks-training.md}}

Ці приклади розглядають різні примітиви локального підвищення привілеїв. Перш ніж застосовувати техніку, перевірте в кожній статті вразливий продукт або версію ядра, конфігурацію та необхідні умови. Для ширшого збору даних про хост скористайтеся [контрольним списком підвищення привілеїв у Linux](../linux-privilege-escalation-checklist.md).

Для Dirty Pipe (CVE-2022-0847) в [оригінальному дослідженні](https://dirtypipe.cm4all.com/) зазначені виправлення в upstream stable: 5.10.102, 5.15.25 і 5.16.11. Версія ядра зі старішого вразливого діапазону — лише привід для перевірки: дистрибутиви можуть переносити виправлення на свої ядра під іншими назвами релізів, а для примітива запису в page-cache цільовий файл має бути доступним для читання. Перезапис доступного для читання виконуваного файла SUID — один із можливих шляхів отримати привілеї, якщо перехід set-ID працює; зміна `/etc/passwd` із подальшою автентифікацією також може залежати від локального стека PAM. Перш ніж оцінювати можливість експлуатації, перевірте встановлений пакет ядра від постачальника, запущене після перезавантаження ядро, дозволи цільового файла, параметр монтування `nosuid` і `no_new_privs`. Не виконуйте пробний запис під час пасивного збору даних. Див. [статус для конкретних випусків Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): виконання з підвищеними привілеями через пошук шляху до процесу з недовірених джерел.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): шлях перезапису page-cache ядра.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): стан гонитви під час обробки таймерів.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): доступ до дескриптора під час стану гонитви при завершенні процесу.

## Пов'язані приклади експлуатації бінарних файлів

У розділі Binary Exploitation детальніше розглядаються примітиви експлуатації, розташування пам'яті та обходи засобів пом'якшення для цих цілей на базі ядра Linux:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): помилку сокета перетворено на примітиви читання й запису в ядрі.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): примітив запису вказівника розширено за допомогою буферів pipe і workqueue.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): експлуатація купи ядра та обходи засобів пом'якшення.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): розгляд стану гонитви таймера з погляду експлуатації бінарних файлів, також стисло описаний вище.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): виявлення адрес для експлуатації ядра arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): шлях через GPU Android до доступу до пам'яті ядра.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): помилка прискорювача Android, використана для запису в ядро.
{{#include ../../../banners/hacktricks-training.md}}
