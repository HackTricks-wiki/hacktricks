# Linux ptrace exit-race `pidfd_getfd()` FD theft

Корисний **Linux kernel privesc pattern** полягає в перетворенні **ptrace authorization bug** на **file descriptor theft** із привілейованого процесу.

У case study Qualys щодо `__ptrace_may_access()` (CVE-2026-46333) attacker створює race з **privileged process, який завершує роботу або скидає credentials**, і використовує `pidfd_getfd()` для дублювання FD у процес attacker.<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()` дублює file descriptor з іншого процесу, але спочатку перевіряє дозволи в стилі ptrace щодо target.<sup>[[3]](#references)</sup> Якщо ця authorization помилково надається під час **teardown window**, unprivileged attacker може скопіювати:

- FD для **sensitive files**, уже відкритих privileged helper
- FD для **authenticated IPC channels**, уже авторизованих як root

Це перетворює kernel-side authorization bug на дуже практичну userspace primitive.<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

Для attack **не потрібен bug безпосередньо в privileged helper**. Helper лише має тимчасово утримувати щось цінне:

- `/etc/shadow`
- `/etc/ssh/*_key`
- привілейоване D-Bus / systemd connection
- будь-який інший уже відкритий secret або authorized channel

Після дублювання в процес attacker копія посилається на той самий open file description, тому подальші reads або IPC requests використовують уже відкритий FD, а не повторно відкривають оригінальний pathname і не запускають новий authentication flow.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Визначити **setuid / setgid / file-capability binary** або **root daemon**, який відкриває sensitive files чи зберігає корисні IPC connections.<sup>[[2]](#references)</sup>
2. Створити relationship, що задовольняє відповідні ptrace policy checks для target path (наприклад, бути **parent** створеного privileged child за permissive налаштувань YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Створити race з процесом, коли він **завершує роботу**, **скидає credentials** або іншим чином переходить у стан, у якому ptrace access уже мав би бути недоступним.<sup>[[2]](#references)</sup>
4. Використати `pidfd_open()` + `pidfd_getfd()` для дублювання target FD протягом вузького authorization window.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Повторно використати stolen FD з unprivileged context.<sup>[[2]](#references)</sup>
- `read()` secrets із privileged file descriptor
- надсилати requests через stolen authenticated IPC channel для отримання **root-side actions**

Мінімальна форма primitive.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Практичні цілі для аудиту

Пріоритезуйте бінарні файли та daemon-и, які навіть короткочасно роблять щось із наведеного:<sup>[[1]](#references)[[2]](#references)</sup>

- відкривають файли, доступні лише root, до завершення переходів привілеїв
- підключаються до **system bus** і зберігають уже авторизований канал
- передають привілейовані FD через межі helper-ів
- виконують чутливу до безпеки роботу під час teardown, суміжного з `do_exit()`

Добрі цілі для пошуку:<sup>[[1]](#references)</sup>

- helper-и для керування паролями / обліковими записами
- SSH helper-и
- helper-и, опосередковані PolicyKit / D-Bus
- root desktop daemon-и, що відкривають D-Bus methods

## YAMA як exploit gate

`kernel.yama.ptrace_scope` є важливим практичним gate для зловживань сімейством ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: класична поведінка ptrace для одного UID
- `1`: зазвичай дозволяє трасування parent -> child, що може залишати доступними деякі public exploit paths
- `2`: для attach-style доступу потрібен `CAP_SYS_PTRACE` і блокується unprivileged зловживання `pidfd_getfd()` у цьому path
- `3`: повністю вимикає ptrace attach до перезавантаження

Для цієї техніки `ptrace_scope=2` є сильним **тимчасовим mitigation**, оскільки ламає public exploitation path `pidfd_getfd()` з `-EPERM` для unprivileged користувачів.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ідеї для виявлення / review

Під час аудиту привілейованого Linux software шукайте такі комбінації:

- **привілейований child process** + **parent під контролем attacker-а**.<sup>[[2]](#references)[[4]](#references)</sup>
- тимчасовий доступ до **цінних відкритих файлів**
- тимчасовий доступ до **автентифікованих D-Bus/systemd channels**.<sup>[[2]](#references)</sup>
- security decisions, що повторно використовують **ptrace-style authorization** поза класичним `ptrace(2)`
- kernel APIs, здатні **дублювати, успадковувати або повторно експортувати** наявні привілейовані FD

Під час аудиту kernel вважайте будь-який path, що виконує **ptrace-equivalent authorization** під час **task teardown**, високоризиковим, особливо якщо успіх надає прямий доступ до `task->files` або інших уже авторизованих process resources.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Локальне підвищення привілеїв до root і розкриття облікових даних у ptrace path Linux kernel (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [TXT advisory від Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Сторінка manual для pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Документація Linux kernel щодо Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Сторінка manual для pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
