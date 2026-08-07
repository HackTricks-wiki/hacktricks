# Linux ptrace exit-race `pidfd_getfd()` крадіжка FD

{{#include ../../../banners/hacktricks-training.md}}

Корисний **Linux kernel privesc pattern** полягає в тому, щоб перетворити **ptrace authorization bug** на **крадіжку file descriptor** із privileged process.

У case study Qualys щодо `__ptrace_may_access()` (CVE-2026-46333) attacker створює race з **privileged process, який завершує роботу або скидає credentials**, і використовує `pidfd_getfd()`, щоб дублювати FD у процес attacker.<sup>[[1]](#references)[[2]](#references)</sup>

## Основна ідея

`pidfd_getfd()` дублює file descriptor з іншого process, але спочатку перевіряє права у стилі ptrace щодо target. Якщо цю authorization помилково надано під час **teardown window**, unprivileged attacker може скопіювати:

- FD для **sensitive files**, які вже відкрив privileged helper
- FD для **authenticated IPC channels**, які вже авторизовані як root

Це перетворює authorization bug на рівні kernel на дуже практичний userspace primitive.<sup>[[1]](#references)</sup>

## Чому цей primitive небезпечний

Для attack **не потрібен bug у самому privileged helper**. Helper має лише тимчасово утримувати щось цінне:

- `/etc/shadow`
- `/etc/ssh/*_key`
- privileged D-Bus / systemd connection
- будь-який інший уже відкритий secret або authorized channel

Після дублювання в процес attacker kernel застосовує operations до **stolen FD**, а не до початкового pathname і не до нового authentication flow.<sup>[[1]](#references)</sup>

## Pattern exploitation

1. Визначити **setuid / setgid / file-capability binary** або **root daemon**, який відкриває sensitive files чи підтримує корисні IPC connections.
2. Отримати relationship, що задовольняє відповідні ptrace policy checks для target path (наприклад, бути **parent** створеного privileged child за permissive налаштувань YAMA).
3. Створити race з процесом, поки він **завершує роботу**, **скидає credentials** або іншим чином переходить у state, у якому ptrace access уже має стати недоступним.
4. Використати `pidfd_open()` + `pidfd_getfd()`, щоб дублювати target FD під час вузького authorization window.
5. Повторно використати stolen FD з unprivileged context:
- `read()` secrets із privileged file descriptor
- надсилати requests через stolen authenticated IPC channel, щоб отримати **root-side actions**<sup>[[1]](#references)</sup>

Мінімальна форма primitive:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Практичні цілі для аудиту

Пріоритезуйте бінарні файли та daemons, які навіть протягом короткого часу виконують одну з таких дій:<sup>[[1]](#references)</sup>

- відкривають файли, доступні лише root, до завершення переходів привілеїв
- підключаються до **system bus** і зберігають уже авторизований канал
- передають привілейовані FD через межі helper-процесів
- виконують чутливі до безпеки дії під час teardown, наближеного до `do_exit()`

Добрі кандидати для пошуку:<sup>[[1]](#references)</sup>

- helper-програми для керування паролями / обліковими записами
- SSH helpers
- helpers, що працюють через PolicyKit / D-Bus
- root desktop daemons, які відкривають D-Bus methods

## YAMA як exploit gate

`kernel.yama.ptrace_scope` є важливим практичним бар'єром для зловживань сімейством ptrace:<sup>[[4]](#references)</sup>

- `0`: класична поведінка ptrace для того самого UID
- `1`: зазвичай дозволяє трасування parent -> child, що може зберігати доступність деяких публічних exploit paths
- `2`: вимагає `CAP_SYS_PTRACE` для доступу у стилі attach і блокує непривілейоване зловживання `pidfd_getfd()` у цьому path
- `3`: повністю вимикає ptrace attach до перезавантаження

Для цієї техніки `ptrace_scope=2` є сильною **тимчасовою мірою захисту**, оскільки ламає публічний шлях експлуатації `pidfd_getfd()` і повертає `-EPERM` для непривілейованих користувачів.<sup>[[1]](#references)</sup>

## Ідеї для виявлення / перевірки

Під час аудиту привілейованого Linux software шукайте такі комбінації:

- **привілейований child process** + **parent, контрольований attacker'ом**
- тимчасовий доступ до **цінних відкритих файлів**
- тимчасовий доступ до **автентифікованих каналів D-Bus/systemd**
- рішення щодо безпеки, які повторно використовують **авторизацію у стилі ptrace** за межами класичного `ptrace(2)`
- kernel APIs, здатні **дублювати, успадковувати або повторно експортувати** вже привілейовані FD

Під час аудиту kernel вважайте шлях, який виконує **еквівалентну ptrace авторизацію** під час **teardown task**, високоризиковим, особливо якщо успіх надає прямий доступ до `task->files` або інших уже авторизованих ресурсів процесу.

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
